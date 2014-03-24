using System;
using System.Net;

using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.Permissions;
using System.DirectoryServices.AccountManagement;

namespace ConnectLDAP
{
    //[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]


    public class LDAPConnect
    {
        #region Fields
        // static variables used throughout the example
        static LdapConnection ldapConnection;
        static string ldapServer;
        static NetworkCredential credential;
        static string targetOU; // dn of an OU. eg: "OU=sample,DC=fabrikam,DC=com"
        static string response;
        static bool result;
  

        #endregion

        #region Properties
        public bool Result
        {
            get
            {
                return result;
            }
        }
 
        public string Response
        {

            get
            {
                return response;
            }
        }
        #endregion

        # region Methods
        //GetParameters property setter
        static void setParameters(string ldapHost, string ldapUser, string ldapPwd, string ldapDomain, string ldapTarget)
        {
            // When running: ConnectLDAP.exe <ldapServer> <user> <pwd> <domain> <targetOU>

            // if (args.Length != 5)
            // {
            //     Console.WriteLine("Usage: ConnectLDAP.exe <ldapServer> <user> <pwd> <domain> <targetOU>");
            //    Environment.Exit(-1);// return an error code of -1
            // }

            // test arguments to insure they are valid and secure

            // initialize variables
            ldapServer = ldapHost;
            credential = new NetworkCredential(ldapUser, ldapPwd);
            targetOU = ldapTarget;
        }

     
        #endregion

        #region Constructor
        /// <summary>
        /// Creates LDAP connection
        /// </summary>
        /// <param name="ldapServer">LDAP server</param>
        /// <param name="user">LDAP user login</param>
        /// <param name="password">LDAP user password</param>
        /// <param name="targetOU">LDAP target OU</param>

        public LDAPConnect(string ldapHost, string ldapUser, string ldapPwd, string ldapDomain, string ldapTarget)
        {
            setParameters(ldapHost, ldapUser, ldapPwd, ldapDomain, ldapTarget);  // Set the properties

            //Create LDAP Entry point
            DirectoryEntry deService = new DirectoryEntry();





            deService.Path = "LDAP://" + ldapHost + "/" + ldapTarget;
            deService.Username = ldapUser;
            //deService .Password = ldapPwd;
            deService.AuthenticationType = AuthenticationTypes.Anonymous;
            //Bind to the native AdsObject to force authentication.			
            Object obj = deService.NativeObject;

            DirectorySearcher dsSearch = new DirectorySearcher(deService);
            dsSearch.Filter = "(cn=" + ldapUser + ")";
            dsSearch.PropertiesToLoad.Add("uid");
            
            try
            {
                SearchResult srResult = dsSearch.FindOne();
                
                if (srResult != null)
                {
                    if (srResult.Properties.Contains("lockoutTime"))
                    {
                        if (Int64.Parse(srResult.Properties["lockoutTime"][0].ToString()) != 0)
                        {
                            //they are locked out... so throw error or return false;
                            result = false;
                            response = "User is locked out";
                        }
                    }
                    //otherwise, verify creds.
                    DirectoryEntry deUser = srResult.GetDirectoryEntry();
                    deUser.Username = ldapUser;
                    deUser.Password = ldapPwd;
                    deUser.AuthenticationType = AuthenticationTypes.Secure;
                    try
                    {
                        //just create a var, it will fail if creds are wrong.
                        string path = deUser.Path;
                        result = false;
                        response = "Good credentials"; // ok, good creds if you got here
                    }
                    catch (Exception ex)
                    {
                        //so, this means their password was bad... NOT the username.
                        result = false;
                        response = "Bad credentials";
                    }
                    finally
                    {
                        deUser.Dispose();
                    }
                }
                else
                {
                    //throw an error here since you did not find the user (bad username)
                    result = false;
                    response = "Did not find user";
                }
            }
            catch (Exception e)
            {
                result = false;
                response = "Authentication server is offline or VPN not established.";
            }
            finally
            {
                deService.Dispose();
                dsSearch.Dispose();
            }
        }

        public LDAPConnect(string ldapHost, string ldapuser, string ldapPwd,string ldapTarget)
        {
            // create a "principal context" - e.g. your domain (could be machine, too)
            using(PrincipalContext pc = new PrincipalContext(ContextType.ApplicationDirectory, ldapHost, ldapTarget))
            {
                // validate the credentials
              
                result = pc.ValidateCredentials("CN=" + ldapuser , ldapPwd);

            }
            //return result;


        }
         #endregion



        public LDAPConnect(string ldapHost,string ldapUser, string ldapPwd)
        {
            try
            {
                setParameters(ldapHost, ldapUser, ldapPwd, "umich.edu", "ou=people,dc=med,dc=umich,dc=edu");  // Set the properties

                // Create the new LDAP connection
                ldapConnection = new LdapConnection(ldapServer);
                ldapConnection.Bind(credential);
                //ldapConnection.Credential = credential;
                //Console.WriteLine("LdapConnection is created successfully.");
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\nUnexpected exception occured:\r\n\t" + e.GetType() + ":" + e.Message);
            }
        }



    }
}