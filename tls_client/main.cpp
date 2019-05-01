#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <fstream>
#include <map>
#include <algorithm>

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

        if(!rst.empty()) {
            _sck->lowest_layer().connect(rst.begin()->endpoint());
            _sck->handshake(ssl::stream_base::client);
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
            return false;
        }
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

    std::cerr << " Q1 " << std::endl;

    clt.write("\ņ");

    if(!clt) {
        std::cerr << "Failed to create proper TlsClient" << std::endl;
        ::exit(1);
    }

    std::string l;

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
            if(!clt.write("EHLO"))
                break;
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
        } else {
            std::cout << " >> ??? " << std::endl;
        }
    };
    return 0;
}
