#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <fstream>
#include <map>
#include <algorithm>

#include "sha1farm.h"

using namespace boost;
using namespace boost::asio;
using ip::tcp;
using std::string;
using std::cout;
using std::endl;

class TlsClient {
public:
    TlsClient(const std::string & srv,const std::string & prt)
        : _ctx(ssl::context::tlsv12_client) {
        std::vector<std::string> pms;
        for(auto const * s : {"a.key","a.cert"}) {
            std::ifstream fi(std::string(::getenv("HOME"))+"/"+s);
            if(!fi.is_open()) {
                throw std::runtime_error(std::string("Failed to open '")+std::string(::getenv("HOME"))+"/"+s+"'");
            }

            std::string l;
            std::stringstream ss;
            while(std::getline(fi,l)) {
                if(!l.empty())
                    ss << l << std::endl;
            }
            pms.push_back(ss.str());
        }

        _ctx.use_private_key(const_buffer(pms[0].c_str(),pms[0].size()), ssl::context::pem);
        _ctx.use_certificate(const_buffer(pms[1].c_str(),pms[1].size()), ssl::context::pem);
        _ctx.set_verify_mode(ssl::verify_none);

        _sck.reset(new ssl::stream<ip::tcp::socket>(_ioc,_ctx));

        ip::tcp::resolver rsv(_ioc);
        ip::tcp::resolver::results_type rst = rsv.resolve(ip::tcp::resolver::query(srv, prt)); ;

        try {
            if(!rst.empty()) {

                boost::system::error_code ec;

                const ip::tcp::resolver::endpoint_type & e = rst.begin()->endpoint();
                std::cerr << "connecting to "<< e.address().to_string() << "/" << e.port() << std::endl;
                _sck->lowest_layer().connect(e);
                std::cerr << "handshaking with "<< rst.begin()->endpoint().address().to_string() << std::endl;
                _sck->handshake(ssl::stream_base::client,ec);
                std::cerr << "handshaking done "<< rst.begin()->endpoint().address().to_string() << "/" << ec << std::endl;
            }
        } catch(std::exception & ex) {
            std::cerr << "EX:" << ex.what() << std::endl;
        }
    }

    bool valid () const {
        return  _sck.get()!=nullptr && _sck->lowest_layer().is_open();
    }

    operator const void * () const {
        return  valid() ? this : nullptr;
    }

    std::string read() {
        asio::streambuf receive_buffer;
        if(valid()) {
            boost::system::error_code error;
            asio::read_until(*_sck, receive_buffer, '\n', error);
        }
        return std::string(asio::buffer_cast<const char*>(receive_buffer.data()),
                        receive_buffer.size()>0 ? receive_buffer.size()-1 : 0);
    }

    bool write(const std::string & l) {
        boost::system::error_code error;
        size_t n = asio::write( *_sck, asio::buffer( (l+'\n').c_str(),(l+'\n').size()), error );
        if( error ) {
            std::stringstream ss;
            ss << "asio::write failed " << error << " '" << error.message() << "'";
            throw std::runtime_error(ss.str());
        }
        std::cout << " << " << l << std::endl;
        return true;
    }

private:
    asio::io_context _ioc;
    ssl::context _ctx;
    std::auto_ptr<ssl::stream<ip::tcp::socket>> _sck;
};


int main() {
    // 8082, 8445, 49154, 3480, 65533, 3335
    TlsClient clt("18.202.148.130", "3335");
    // TlsClient clt("www.google.com", "443");

    if(!clt) {
        std::cerr << "Failed to create proper TlsClient" << std::endl;
        ::exit(1);
    }
    try {
        std::string l;
        std::string auth;
        std::auto_ptr<Sha1Farm> sha1farm;

        while( (l = clt.read()) != "") {
            std::stringstream ss(l);
            std::vector<std::string> args;
            std::string a;

            while(std::getline(ss,a,' ')) {
                if(!a.empty()) {
                    args.push_back(a);
                }
            }

            std::cout << " >> ";
            bool f=false;
            for(const auto & a : args) {
                std::cout << (f ? "" : " ") << "[" << a << "]";
            }

            std::cout << std::endl;

            if(args[0] == "HELO") {
                if(args.size()!=1) {
                    throw std::runtime_error("Expected 0 args");
                }
                clt.write("EHLO");
            } else if(args[0]=="POW") {
                if(args.size()!=3) {
                    throw std::runtime_error("Expected 2 args");
                }
                std::string prefix = args[1];
                std::stringstream ss(args[2]);
                int n=0;
                if( !(ss >> n && ss.eof()) ) {
                    throw std::runtime_error("Expected arg 2 to be an integer");
                }
                auth = args[1];
                sha1farm.reset(new Sha1Farm(args[1],n));
                std::cerr << "..caclulating suffix '"+args[1]+"'/" << n << "..." << std::endl;
                sha1farm->run();
                if(sha1farm->sucess()) {
                    clt.write(sha1farm->suffix());
                }
             } else if(args[0] == "ERROR") {
                break;
             } else if(args[0] == "END") {
                clt.write("OK");
                break;
             } else if(args[0] == "NAME") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "Sebastian Kloska");
             } else if(args[0] == "MAILNUM") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "1");
            } else if(args[0] == "MAIL1")  {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "sebastian.kloska@snafu.de");
            } else if(args[0] == "SKYPE") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "oncaphillis");
            } else if(args[0] == "BIRTHDATE") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "25.12.1962");
            } else if(args[0] == "COUNTRY") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "Germany");
            } else if(args[0] == "ADDRNUM") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "2");
            } else if(args[0] == "ADDRLINE1" ) {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "Hohenstaufenstr 67");
            } else if(args[0] == "ADDRLINE2") {
                if(args.size()!=2) {
                    throw std::runtime_error("Expected 1 arg");
                }
                clt.write(Sha1Farm::sha1(auth + args[1]) + " " + "10781 Berlin");
            } else {
                std::cerr << " !! " << l << std::endl;
            }
        };
    } catch(std::exception & ex) {
        std::cerr << "EX:'" << ex.what() << "'" << std::endl;
    }

    return 0;
}
