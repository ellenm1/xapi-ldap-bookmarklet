//
// Don't forget to remove the HTML tags above and at the end of the file
using System;
using System.Collections;
using System.Xml;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.DirectoryServices.Protocols;
using System.Web;
using System.IO;



namespace ConnectUmichLDAP
{

    /// 
    /// Example of LDAP Authentication code using ADSI with MCIT custom error messages
    /// written by Dmitriy Kashchenko, IDM team
    public class LdapAuthentication
    {
        # region fields
        // const
        private const string ERR_NOT_FOUND = "(0x80072030): not found";

        // LDAP metrics
        private string _ldapserver = "LDAP://ldap.ent.med.umich.edu:636/";
        private string _topContainer = "ou=people,dc=med,dc=umich,dc=edu";
        private String _defaultFilter = "(uid={0})";

        // errors handling
        // messages file name
        private string _messages = "ldapautherrors.xml";
        // variables
        private string _errorMsg;
        private string _provider;
        private const string nodeKey = "message";
        private const string indexAttr = "index";
        private Hashtable errors = null;
        #endregion

        # region methods
        private void parseFile(string fname)
        {
            string virtualPath = "HTTP://"  + HttpContext.Current.Request.Url.Authority  + HttpContext.Current.Request.ApplicationPath + "/" + fname;
            XmlTextReader node = new XmlTextReader(virtualPath);
            node.WhitespaceHandling = WhitespaceHandling.None;

            while (node.Read())
            {
                if (node.NodeType == XmlNodeType.Element && node.Name.Equals(nodeKey))
                {
                    if (node.HasAttributes)
                    {
                        string index = node.GetAttribute("index");
                        node.Read();
                        string message = node.Value;
                        errors.Add(index, message);
                    }
                }
            }

            node.Close();
        }

        [DllImport("activeds.dll", ExactSpelling = true, EntryPoint = "ADsGetLastError", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int ADsGetLastError(ref int error, IntPtr errorbuf, int errorbuflen, IntPtr namebuf, int namebuflen);

        private int getExtendedError()
        {
            IntPtr errorbuf = (IntPtr)0;
            IntPtr namebuf = (IntPtr)0;
            int error = 0;

            try
            {
                errorbuf = Marshal.AllocHGlobal(256 * 2);
                namebuf = Marshal.AllocHGlobal(256 * 2);
                ADsGetLastError(ref error, errorbuf, 256, namebuf, 256);
                _errorMsg = Marshal.PtrToStringUni(errorbuf);
                _provider = Marshal.PtrToStringUni(namebuf);

                return error;
            }
            finally
            {
                if (errorbuf != (IntPtr)0) Marshal.FreeHGlobal(errorbuf);
                if (namebuf != (IntPtr)0) Marshal.FreeHGlobal(namebuf);
            }
        }

        public string getErrorMessage(Exception e)
        {
            string rc = e.ToString();
            if (errors != null)
            {
                int ee = getExtendedError();
                if (ee != 0) rc = _errorMsg;
                foreach (DictionaryEntry entry in errors)
                {
                    string index = (string)entry.Key;
                    if (rc.IndexOf(index) != -1)
                    {
                        rc = (string)entry.Value;
                        break;
                    }
                }
            }

            return  rc;
        }

        #endregion

        #region constructor
        /// <summary>
        /// Creates new UMICH LDAP array with the user's email address and userName
        /// </summary>
        public LdapAuthentication()
        {
            errors = new Hashtable();
            parseFile(_messages);
        }
        #endregion

        /// <summary>
        /// Old authentication method, don't use
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public string[] AuthenticateOld(string user, string password)
        {
            string[] results = new string[2];


            //Concatenate serverpath + username + container
            //I.e.  "LDAP://ldap.disney.com:636/CN=donaldDuck,ou=people,dc=la,dc=disney,dc=com"
            DirectoryEntry de = new DirectoryEntry(_ldapserver + "cn=" + user + "," + _topContainer);
            //+ "cn=" + user + ","
            de.Username = "cn=" + user + "," + _topContainer;


            //User's password for initial verification
            de.Password = password;

            //initate anonymous bind
            de.AuthenticationType = System.DirectoryServices.AuthenticationTypes.SecureSocketsLayer;
            DirectorySearcher searcher = new DirectorySearcher(de);
            searcher.PropertiesToLoad.Add("sn");
            searcher.PropertiesToLoad.Add("mail");
            searcher.PropertiesToLoad.Add("givenName");
            //Search for first record
            SearchResult result = searcher.FindOne();

            //Check results
            if (result == null) throw new Exception(ERR_NOT_FOUND);

            de = result.GetDirectoryEntry();
            //Validate password, this will trigger exception if user not found
            Object obj1 = de.NativeObject;

            //Return search results
            results[0] = (string)de.Properties["mail"].Value;
            results[1] = (string)de.Properties["givenName"].Value + " " + (string)de.Properties["sn"].Value;
            // Distingushed Name of the found account
            //string DN = de.Path.Substring(de.Path.ToUpper().IndexOf("CN="));
            // Close search connection
            searcher.Dispose();
            de.Close();

            //if we made it here, we successfully authenticated
            return results;
        }

       /// <summary>
       /// Authenticates user against UMICH LDap server and returns array[2] with user email and full name
       /// </summary>
       /// <param name="user"></param>
       /// <param name="password"></param>
       /// <returns></returns>
 
        public string[] AuthenticateLDAP(string user, string password)
        {
            string[] results = new string[2];

            DirectoryEntry de = new DirectoryEntry(_ldapserver + _topContainer);
            // required to initate anonymous bind
            de.AuthenticationType = System.DirectoryServices.AuthenticationTypes.ServerBind;
            DirectorySearcher searcher = new DirectorySearcher(de);

            //set the filter to search UID first. 
            //the filter syntax is the standard LDAP filter syntax
            //Cannot authenticate against UID/pwd combo, only CN/pwd combo
            //So we search on UID, to find CN
            searcher.Filter = string.Format(_defaultFilter, user);
            SearchResult result = searcher.FindOne();
            if (result == null) throw new Exception(ERR_NOT_FOUND);

            de = result.GetDirectoryEntry();
            // Distingushed Name of the found account, 
            // extract CN for authentication
            string DN = de.Path.Substring(de.Path.ToUpper().IndexOf("CN="));

            // Close search connection and free resources up
            de.Close();
            searcher.Dispose();

            // now bind with CN and authenticate user
            //Concatenate serverpath + username + container
            //I.e.  "LDAP://ldap.disney.com:636/CN=donaldDuck,ou=people,dc=la,dc=disney,dc=com"
            de = new DirectoryEntry(_ldapserver + "cn=" + user + "," + _topContainer);
            de.Username = DN;
            de.Password = password;
            de.AuthenticationType = System.DirectoryServices.AuthenticationTypes.SecureSocketsLayer;
            Object obj = de.NativeObject;

            //We need to re initiate DirectorySearcher so that we can specify/limit the properties loaded
            searcher = new DirectorySearcher(de);
            searcher.PropertiesToLoad.Add("sn");
            searcher.PropertiesToLoad.Add("mail");
            searcher.PropertiesToLoad.Add("givenName");

            //Now Search again for first record found
            SearchResult result2 = searcher.FindOne();
            de = result2.GetDirectoryEntry();

            //Store search results for return
            results[0] = (string)de.Properties["mail"].Value;
            results[1] = (string)de.Properties["givenName"].Value + " " + (string)de.Properties["sn"].Value;

            //Clean up resources
            de.Close();
            searcher.Dispose();

            //return string array
            return results;
        }
    }
}