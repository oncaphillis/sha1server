#include <time.h>
#include <CL/cl.hpp>

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>

class ClFarm {

public:

    ClFarm(const std::string & code,const std::string & kernel) {
        cl_int status;

        std::vector<cl::Platform> pfs;

        status = cl::Platform::get( &pfs );

        if (status != CL_SUCCESS) {
            throw std::runtime_error("Error: Getting platforms!");
        }

        if (pfs.empty()) {
            throw std::runtime_error("Error: No platforms!");
        }

        for(const auto & pf : pfs) {
            std::cerr << "PF:'" << pf.getInfo<CL_PLATFORM_NAME>() << "'" << std::endl;

            std::vector<cl::Device> dvs;
            status = pf.getDevices(CL_DEVICE_TYPE_GPU, &dvs );

            for(const auto & dv : dvs) {
                std::cerr << " DV:'" << dv.getInfo<CL_DEVICE_NAME>() << "'" << std::endl;
            }

            if( status == CL_DEVICE_NOT_FOUND) {
                continue;
            }

            if (status != CL_SUCCESS  ) {
                std::stringstream ss;
                ss << "Error gettig devices for platform " << pf.getInfo<CL_PLATFORM_NAME>() << " #" << status;
                throw std::runtime_error(ss.str());
            }

            if(dvs.empty()) {
                std::cerr << " pf:#" << pf.getInfo<CL_PLATFORM_NAME>() << " gpus==nil";
                continue;
            }

            for(auto dv : dvs) {
                std::cerr << " pf:#" << pf.getInfo<CL_PLATFORM_NAME>() << " dv:" << dv.getInfo<CL_DEVICE_NAME>() << std::endl;
            }

            _platforms.push_back(pf);
            _devices.push_back( dvs[0] );
            break;

        }

        if( _platforms.empty() || _devices.empty() ) {
            throw std::runtime_error("Failed to get a real GPU on any platform");
        }

        _context.reset(new cl::Context(_devices[0]));

        _queue.reset(new cl::CommandQueue(*_context,_devices[0]));
        _program.reset(new cl::Program(*_context,code));

        status = _program->build(_devices);

        if(status != CL_SUCCESS) {
            throw std::runtime_error(_program->getBuildInfo<CL_PROGRAM_BUILD_LOG>(_devices[0]));
        }

        _kernel.reset(new cl::Kernel(*_program,kernel.c_str(),&status));

        if(status != CL_SUCCESS) {
            throw std::runtime_error("failed to get kernel '"+kernel+"'");;
        }
    }

    ClFarm(std::istream &is,const std::string & kernel) :
        ClFarm(fromStream(is),kernel) {
    }

    ~ClFarm() {
    }

    void run() {
        _global_ws[0] = 1;
        _local_ws[0] = 1;

        cl::Buffer buffer_A(*_context,CL_MEM_READ_WRITE,sizeof(cl_int) * 10);
        cl::Buffer buffer_B(*_context,CL_MEM_READ_WRITE,sizeof(cl_int) * 10);
        cl::Buffer buffer_C(*_context,CL_MEM_READ_WRITE,sizeof(cl_int) * 10);

        //write arrays A and B to the device

        cl_int A[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        cl_int B[] = {10, 11, 12, 10, 11, 12, 10, 11, 12, 10};
        cl_int C[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        _queue->enqueueWriteBuffer(buffer_A,CL_TRUE,0,sizeof(cl_int)*10,A);
        _queue->enqueueWriteBuffer(buffer_B,CL_TRUE,0,sizeof(cl_int)*10,B);

        cl::Kernel test_kernel(*_program,"test_kernel");

        test_kernel.setArg(0,buffer_A);
        test_kernel.setArg(1,buffer_B);
        test_kernel.setArg(2,buffer_C);

        _queue->enqueueNDRangeKernel(test_kernel,cl::NullRange,cl::NDRange(128),cl::NDRange(4));
        _queue->finish();
        _queue->enqueueReadBuffer(buffer_C,CL_TRUE,0,sizeof(cl_int)*10,C);

        for(auto c : C) {
            std::cerr << c << "::";
        }
        std::cerr << std::endl;
    }
private:
    static std::string fromStream(std::istream &is) {
        std::stringstream ss;
        if(!is)
            throw std::runtime_error("Failed to read from stream");
        std::string l;
        while(std::getline(is,l)) {
            ss << l << std::endl;
        }
        return ss.str();
    }

    std::vector<cl::Platform> _platforms;
    std::vector<cl::Device> _devices;

    std::unique_ptr<cl::Context > _context;
    std::unique_ptr<cl::Program > _program;
    std::unique_ptr<cl::Kernel > _kernel;
    std::unique_ptr<cl::CommandQueue> _queue;

    size_t _global_ws[1];
    size_t _local_ws[1];
};

int main() {
    std::ifstream fs("./sha1.cl");
    std::cerr << "*1*" <<std::endl;
    ClFarm f(fs,"test_kernel");
    std::cerr << "*2*" <<std::endl;
    f.run();
    return 0;
}
