//#include "stdafx.h"
#include<stdio.h>
#include<time.h>
#include <iostream>
#include <string>
#include <fstream>
#include <stdio.h>
//#include <dir.h>
using std::cout;
using std::endl;
using std::ostream;  // NOLINT
#include <memory>
#include "googleapis/client/auth/file_credential_store.h"
#include "googleapis/client/auth/oauth2_authorization.h"
#include "googleapis/client/data/data_reader.h"
#include "googleapis/strings/stringpiece.h"
#include <openssl/evp.h>
//#if HAVE_OPENSSL
#include "googleapis/client/data/openssl_codec.h"
//#endif
#include "googleapis/client/transport/curl_http_transport.h"
#include "googleapis/client/auth/file_credential_store.h"
#include "googleapis/client/transport/http_authorization.h"
#include "googleapis/client/transport/http_transport.h"
#include "googleapis/client/transport/http_request_batch.h"
#include "googleapis/client/util/status.h"
#include "googleapis/strings/strcat.h"
#include "googleapis/client/data/data_reader.h"
#include "googleapis/client/data/data_writer.h"
#include "googleapis/client/transport/http_transport.h"
#include "googleapis/client/transport/http_request.h"
#include "googleapis/client/transport/http_response.h"
#include "googleapis/client/transport/http_types.h"


//#include "google/calendar_api/calendar_api.h"
#include "service_apis/gmail/google/gmail_api/gmail_api.h"    // NOLINT

namespace googleapis {
    
    //DEFINE_string(client_secrets_path, "","REQUIRED: Path to JSON client_secrets file for OAuth.");
    
    using namespace std;
    using std::cin;
    using std::cout;
    using std::cerr;
    using std::endl;
    
    using google_gmail_api::Message;
    using google_gmail_api::History;
    using google_gmail_api::Thread;
    using google_gmail_api::GmailService;
    using google_gmail_api::ListMessagesResponse;
    using google_gmail_api::UsersResource_MessagesResource_ListMethod;
    
    using client::DataReader;
    using client::DataWriter;
    using client::HttpHeaderMap;
    using client::HttpRequest;
    using client::HttpRequestState;
    using client::HttpResponse;
    using client::HttpTransport;
    using client::HttpTransportFactory;
    using client::HttpTransportLayerConfig;
    using client::HttpTransportOptions;
    
    
    using client::ClientServiceRequest;
    using client::DateTime;
    using client::CredentialStore;
    using client::FileCredentialStoreFactory;
    using client::HttpRequestBatch;
    using client::HttpResponse;
    using client::HttpTransport;
    using client::HttpTransportLayerConfig;
    using client::JsonCppArray;
    using client::OAuth2Credential;
    using client::OAuth2AuthorizationFlow;
    using client::OAuth2RequestOptions;
#if HAVE_OPENSSL
    using client::OpenSslCodecFactory;
#endif
    using client::StatusCanceled;
    using client::StatusInvalidArgument;
    using client::StatusOk;
    
    const char kSampleStepPrefix[] = "SAMPLE:  ";
    
    static googleapis::util::Status PromptShellForAuthorizationCode(
                                                                    OAuth2AuthorizationFlow* flow,
                                                                    const OAuth2RequestOptions& options,
                                                                    string* authorization_code) {
        string url = flow->GenerateAuthorizationCodeRequestUrlWithOptions(options);
        std::cout << "Enter the following URL into a browser:\n" << url << std::endl;
        std::cout << std::endl;
        std::cout << "Enter the browser's response to confirm authorization: ";
        //options.OAuth2RequestOptions::
        authorization_code->clear();
        std::cin >> *authorization_code;
        if (authorization_code->empty()) {
            return StatusCanceled("Canceled");
        } else {
            return StatusOk();
        }
    }
    
    static googleapis::util::Status ValidateUserName(const string& name) {
        if (name.find("/") != string::npos) {
            return StatusInvalidArgument("UserNames cannot contain '/'");
        } else if (name == "." || name == "..") {
            return StatusInvalidArgument(
                                         StrCat("'", name, "' is not a valid UserName"));
        }
        return StatusOk();
    }
    
    void DisplayError(ClientServiceRequest* request) {
        const HttpResponse& response = *request->http_response();
        std::cout << "====  ERROR  ====" << std::endl;
        std::cout << "Status: " << response.status().error_message() << std::endl;
        if (response.transport_status().ok()) {
            std::cout << "HTTP Status Code = " << response.http_code() << std::endl;
            std::cout << std::endl
            << response.body_reader()->RemainderToString() << std::endl;
        }
        std::cout << std::endl;
    }

    
    StringPiece Display(const string& prefix, const Message& entry) {
        std::cout << prefix << "Calendar" << std::endl;
        std::cout << prefix << "  ID: " << entry.get_id() << std::endl;
       
        std::cout << prefix << "  Snippet: " << entry.get_history_id() << std::endl;
        
        return entry.get_id();
            }
    
    template <class LIST, typename ELEM>
    void DisplayList(
                     const string& prefix, const string& title, const LIST& list) {
        std::cout << prefix << "====  " << title << "  ====" << std::endl;
        string sub_prefix = StrCat(prefix, "  ");
        bool first = true;
        const JsonCppArray<ELEM>& items = list.get_messages();
        for (typename JsonCppArray<ELEM>::const_iterator it = items.begin();
             it != items.end();
             ++it) {
            if (first) {
                first = false;
            } else {
                std::cout << std::endl;
            }
            Display(sub_prefix, *it);
        }
        if (first) {
            std::cout << sub_prefix << "<no items>" << std::endl;
        }
    }
    
    
    static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }
    
    std::string base64_decode(std::string const& encoded_string) {
        static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
        long in_len = encoded_string.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::string ret;
        
        while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i ==4) {
                for (i = 0; i <4; i++)
                    char_array_4[i] = base64_chars.find(char_array_4[i]);
                
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
                
                for (i = 0; (i < 3); i++)
                    ret += char_array_3[i];
                i = 0;
            }
        }
        
        if (i) {
            for (j = i; j <4; j++)
                char_array_4[j] = 0;
            
            for (j = 0; j <4; j++)
                char_array_4[j] = base64_chars.find(char_array_4[j]);
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
        }
        
        return ret;
    }


    std::string timeStampToHReadble(const time_t rawtime)
    {
        struct tm * dt;
        char buffer [30];
        dt = localtime(&rawtime);
        strftime(buffer, sizeof(buffer), "%a, %d %b %YYYY %HH:%MM:%SS", dt);
        return std::string(buffer);
    }
    
    //"1998-04-11" format
    time_t convertToTimeStamp(std::string input){
        struct tm tm;
        time_t ts = 0;
        memset(&tm, 0, sizeof(tm));
        
        strptime(input.c_str(), "%Y-%m-%d", &tm);
        ts = mktime(&tm);
        return ts;
    }
    
    
    string encryptDecrypt(string toEncrypt) {
        if(toEncrypt.size() == 0){
           return "";
        }
        char key[13] = {'K', 'C', 'Q','M','W','A','D','S','F','T','I','Z','B'}; //Any chars will work
        string output = toEncrypt;
        
        for (int i = 0; i < toEncrypt.size(); i++)
            output[i] = toEncrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];
        
        return output;
    }
    
    
    
    class GmailSample {
    public:
        static googleapis::util::Status Startup(int argc, char* argv[]);
        void Run();
        
    private:
        // Gets authorization to access the user's personal calendar data.
        googleapis::util::Status Authorize();
        
        
        
         void ListMessages();
        
        void displayDecryptedFile(std::string path);
        
        
        
        OAuth2Credential credential_;
        static std::unique_ptr<GmailService> service_;
        static std::unique_ptr<OAuth2AuthorizationFlow> flow_;
        static std::unique_ptr<HttpTransportLayerConfig> config_;
    };
    
    // static
    std::unique_ptr<GmailService> GmailSample::service_;
    std::unique_ptr<OAuth2AuthorizationFlow> GmailSample::flow_;
    std::unique_ptr<HttpTransportLayerConfig> GmailSample::config_;
    HttpTransportOptions opt;
    
    
    
    /* static */
    util::Status GmailSample::Startup(int argc, char* argv[]) {

        
        // Set up HttpTransportLayer.
        googleapis::util::Status status;
        config_.reset(new HttpTransportLayerConfig);
        client::HttpTransportFactory* factory =
        new client::CurlHttpTransportFactory(config_.get());
        config_->ResetDefaultTransportFactory(factory);

        const std::string capath("/Users/Divakar/Documents/My apps /C++/Secure My Email/Secure My Email/roots.pem");
        
       
        
        config_->mutable_default_transport_options()->set_cacerts_path(capath.c_str());
        
        const string client_secrets_file = "/Users/Divakar/Documents/My apps /C++/Secure My Email/Secure My Email/gmail_sceret.json";
        
        Json::Reader reader;
        Json::Value root;
        std::ifstream stream(client_secrets_file, std::ifstream::binary);
        if(!reader.parse(stream, root)){
            std::cout << " no json " << std::endl;
        } else {
            std::cout << " yes json"  << std::endl;
            std::string encoding = root.get("encoding", "UTF-8" ).asString();
            std::cout << encoding << "\n";
           // std::cout << root << "\n";
        }
        Json::FastWriter fastWriter;
        std::string output = fastWriter.write(root);

        
        // Set up OAuth 2.0 flow for getting credentials to access personal data.
        //const string client_secrets_file = argv[1];
        flow_.reset(OAuth2AuthorizationFlow::MakeFlowFromClientSecretsJson(
                                                                           output , config_->NewDefaultTransportOrDie(), &status));
        if (!status.ok()) return status;
        
        flow_->set_default_scopes(GmailService::SCOPES::GMAIL_READONLY);
        flow_->mutable_client_spec()->set_redirect_uri(
                                                       OAuth2AuthorizationFlow::kOutOfBandUrl);
        flow_->set_authorization_code_callback(
                                               NewPermanentCallback(&PromptShellForAuthorizationCode, flow_.get()));
        
        
        string home_path;
        status = client::FileCredentialStoreFactory::GetSystemHomeDirectoryStorePath(&home_path);
        if (status.ok()) {
            client::FileCredentialStoreFactory store_factory(home_path);
            // Use a credential store to save the credentials between runs so that
            // we dont need to get permission again the next time we run. We are
            // going to encrypt the data in the store, but leave it to the OS to
            // protect access since we do not authenticate users in this sample.
//#if HAVE_OPENSSL
            client::OpenSslCodecFactory* openssl_factory = new client::OpenSslCodecFactory;
            status = openssl_factory->SetPassphrase(
                                                    flow_->client_spec().client_secret());
            if (!status.ok()) return status;
            store_factory.set_codec_factory(openssl_factory);
//#endif
            
            flow_->ResetCredentialStore(
                                        store_factory.NewCredentialStore("GmailSample", &status));
        }
        if (!status.ok()) return status;
        
        // Now we'll initialize the calendar service proxy that we'll use
        // to interact with the calendar from this sample program.
        HttpTransport* transport = config_->NewDefaultTransport(&status);
        
        if (!status.ok()) return status;
        
        service_.reset(new GmailService(transport));
        return status;
    }
    
    
    util::Status GmailSample::Authorize() {
        std::cout
        << std::endl
        << "Welcome to the Google APIs for C++ CalendarSample.\n"
        << "  You will need to authorize this program to look at your calendar.\n"
        << "  If you would like to save these credentials between runs\n"
        << "  (or restore from an earlier run) then enter a Google Email "
        "Address.\n"
        << "  Otherwise just press return.\n" << std::endl
        << "  Address: ";
        string email;
        std::getline(std::cin, email);
        if (!email.empty()) {
            googleapis::util::Status status = ValidateUserName(email);
            if (!status.ok()) {
                return status;
            }
        }
        
        OAuth2RequestOptions options;
        options.email = email;
        googleapis::util::Status status =
        flow_->RefreshCredentialWithOptions(options, &credential_);
        if (!status.ok()) {
            return status;
        }
        
        credential_.set_flow(flow_.get());
        std::cout << "Authorized " << email << std::endl;
        return StatusOk();
    }
    
    
        void GmailSample::ListMessages()
        {
            const StringPiece userId(credential_.email());
            std::unique_ptr<UsersResource_MessagesResource_ListMethod> method(
                                                                              service_->get_users().get_messages().NewListMethod(&credential_, userId));
            
            std::string mail;
            std::string from;
            std::string sub;
            std::string date;
            const char *path="/Users/Divakar/Documents/My apps /C++/Secure My Email/Secure My Email/mail/";
            
            //GetMethod
    
            std::unique_ptr<google_gmail_api::ListMessagesResponse> msg_list(google_gmail_api::ListMessagesResponse::New());
            if (!method->ExecuteAndParseResponse(msg_list.get()).ok())
            {
                std::cout << "\n Failure to read" << std::endl;
                return;
            }
    
            if (msg_list.get()->has_messages())
            {
                std::cout << "\n Has messages" << std::endl;
                std::cout << msg_list.get()->get_result_size_estimate() << std::endl;
                std::cout << "Please enter dates in this format YYYY-MM-DD .." << endl;
                std::cout << "please enter start date .." << endl;
                std::string startDate;
                getline (cin, startDate);
                
                std::cout << "please enter end date .." << endl;
                std::string endDate;
                getline (cin, endDate);
                
                std::cout << "please wait this may take a while ..." << endl;
               // int stat;
                
                //stat = system("mkdir -p " + std::string(path) + startDate + " to "+endDate "");
                //mkdir(path+startDate+" to "+endDate);
//                if (!stat)
//                    printf("Directory created\n");
//                else
//                {
//                    printf("Unable to create directory\n");
//                    exit(1);
//                }
                
                
                int start = (int)convertToTimeStamp(startDate);
                int end = (int)convertToTimeStamp(endDate);
                end += 24 * 60 * 60;
                
                const JsonCppArray<Message>& items = msg_list->get_messages();
                for (typename JsonCppArray<Message>::const_iterator it = items.begin();
                     it != items.end(); ++it)
                     {

                    StringPiece id = (*it).get_id();
                    google_gmail_api::UsersResource_MessagesResource_GetMethod newmethod(service_.get(),&credential_, userId,id);
                         
                    std::unique_ptr<Message> msg(Message::New());
                    if (!newmethod.ExecuteAndParseResponse(msg.get()).ok())
                    {
                        std::cout << "\n Message Failure to parse" << std::endl;
                    }
                         int64 num = msg.get()->get_internal_date();
                        std::string s = std::to_string(num);
                         //std::string ss = (string)str;
                         while(s.size() != 10){
                             s = s.substr(0, s.size()-1);
                         }
                         num = stoi(s);
//                         time_t t;
//                         std::ifstream input(s);
//                         // ...
//                         input >> t;
//                         std::string timestamp = timeStampToHReadble(t);
//                         
//                         std::cout << timestamp << std::endl;
                         
                         if(num > start && num < end){
                             
                         //std::cout << "\n in" << std::endl;
                         
                       
                         google_gmail_api::MessagePart pl = msg.get()->get_payload();
                        // google_gmail_api::MessagePartBody mb = pl.get_body();
                         client::JsonCppArray<google_gmail_api::MessagePart> innnerParts = pl.get_parts();
                         client::JsonCppArray<google_gmail_api::MessagePartHeader> headers = pl.get_headers();
                         if(!headers.empty()){
                             for (typename JsonCppArray<google_gmail_api::MessagePartHeader>::const_iterator k = headers.begin();
                                  k != headers.end(); ++k)
                             {
                                 if((*k).get_name() == "Subject"){
                                     sub = (*k).get_value().as_string();
                                 }
                                 if((*k).get_name() == "From"){
                                     from = (*k).get_value().as_string();
                                 }
                                 if((*k).get_name() == "Date"){
                                     date = (*k).get_value().as_string();
                                 }

                                 
                             }
                         }
                         
                         if(!innnerParts.empty()){
                             bool haveMail =false;
                         for (typename JsonCppArray<google_gmail_api::MessagePart>::const_iterator i = innnerParts.begin();
                              i != innnerParts.end(); ++i)
                         {
                             
                            // if((*i).get_mime_type() == "text/plain"){
                                 if(!haveMail){
                                 haveMail = true;
                                 }
                         google_gmail_api::MessagePartBody inpart((*i).get_body());
                             
                             if(inpart.has_data()){
                                 if(haveMail){
                                     mail.append("\n");
                                    
                                     mail.append(base64_decode(inpart.get_data().as_string()));
                                 } else {
                                 mail = base64_decode(inpart.get_data().as_string());
                                 //std::cout << "\n " << mail << std::endl;
                                 }
                          
                           //  }
                            }
                             }
                         }
                   
                         std::ofstream outputFile(path+ sub + ".txt");
                             std::string newFrom =  encryptDecrypt(from);
                             std::string newDate = encryptDecrypt(date);
                             std::string newSub = encryptDecrypt(sub);
                             std::string newMail = encryptDecrypt(mail);
                             
                         //outputFile.open(sub+".txt");
                         outputFile << encryptDecrypt("From :\n") << endl;
                        outputFile << newFrom << endl;
                         outputFile << "\n" << endl;
                         outputFile << "\n" << endl;
                         outputFile << encryptDecrypt("Date : \n") << endl;
                         outputFile << newDate << endl;
                         outputFile << "\n" << endl;
                         outputFile << "\n" << endl;
                         outputFile << encryptDecrypt("Subject : \n") << endl;
                         outputFile << newSub << endl;
                         outputFile << "\n" << endl;
                         outputFile << "\n" << endl;
                         outputFile << encryptDecrypt("Mail body : \n") << endl;
                         outputFile << newMail << endl;
                         outputFile.close();
                         
                         mail = "";
                         newFrom =  "";
                         newDate = "";
                         newSub = "";
                         newMail = "";
                         
               
                         
                }

                    sub = "";
                    from = "";
                    date = "";
                
                
            }
            }
    
            std::cout << "All mail in tha time period is fetched ecrypted and stored " << std::endl;
        }
    
    string toDisplay(string line){
        string fromTxt = "From :";
        string dateTxt ="Date : ";
        string subTxt = "Subject : ";
        string mailTxt = "Mail body : ";
        if(line == fromTxt){
            return fromTxt;
        }
        else if(line == dateTxt){
            return dateTxt;
        }
        else if(line == subTxt){
            return subTxt;
        }
        else if(line == mailTxt){
            return mailTxt;
        }
        else if( line != fromTxt && line != dateTxt && line != subTxt && line != mailTxt && line != "" && line.size() != 0){
           return encryptDecrypt(line);
            
        } else {
            return "";
        }
        
        return "";
    }
    
    void GmailSample::displayDecryptedFile(std::string path){
        string line;
        
        string dir = "/Users/Divakar/Documents/My apps /C++/Secure My Email/Secure My Email/mail/";
        ifstream myfile (dir+path+".txt");
        if (myfile.is_open())
        {
            while ( getline (myfile,line) )
            {
            cout << encryptDecrypt(line) << '\n';
            }
            myfile.close();
        }
        
        else cout << "Unable to open file";

        
    }
    
    
       
    void GmailSample::Run() {
        std::cout << kSampleStepPrefix << "Getting User Authorization" << std::endl;
        googleapis::util::Status status = Authorize();
        if (!status.ok()) {
            std::cout << "Could not authorize: " << status.error_message() << std::endl;
            return;
        }
        
        //Authorize();
        
        std::cout << std::endl
        << kSampleStepPrefix << "Showing mail" << std::endl;
          ListMessages();
        
        std::cout << "Do you want to see any decrypted mail. " << std::endl;
        std::cout << "Press Y for yes and N for No " << std::endl;
        std::string userInput;
        getline (cin, userInput);
        if(userInput == "Y" || userInput == "y"){
            
            std::cout << "Enter the file name you want to Decrypt" << std::endl;
            std::string fileName;
            getline(cin, fileName);
            displayDecryptedFile(fileName);
            
        }else{
            
            std::cout << "Decryption process skiped" << std::endl;

            
        }
        
        
    }
    
    
}  // namespace googleapis

using namespace googleapis;
int main(int argc, char* argv[]) {
    
    googleapis::util::Status status = GmailSample::Startup(argc, argv);
    if (!status.ok()) {
        std::cerr << "Could not initialize application." << std::endl;
        std::cerr << status.error_message() << std::endl;
        return -1;
    }
    
    GmailSample sample;
    sample.Run();
    std::cout << "Done!" << std::endl;
    
    return 0;
}
