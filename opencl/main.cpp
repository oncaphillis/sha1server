#include <time.h>

#include <iostream>
#include <iomanip>

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#define FORMAT_LABEL			"sha1-opencl"
#define FORMAT_NAME				"SHA-1"
#define ALGORITHM_NAME			"sha1-opencl develop only"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		64

#define BINARY_SIZE			20
#define SALT_SIZE			0

#define SHA_NUM_KEYS               	1024*2048

#define MIN_KEYS_PER_CRYPT		2048
#define MAX_KEYS_PER_CRYPT		SHA_NUM_KEYS

#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define MAX_SOURCE_SIZE 0x10000000

cl_platform_id platform_id = NULL;
cl_device_id device_id = NULL;  
cl_uint ret_num_devices;
cl_uint ret_num_platforms;
cl_context context;

cl_int ret;

char* source_str;
size_t source_size;

cl_program program;
cl_kernel kernel;
cl_command_queue command_queue;


cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys, data_info;
cl_uint *partial_hashes;
cl_uint *res_hashes;
char *saved_plain;
unsigned int datai[3];
int have_full_hashes;

size_t kpc = 4;

size_t global_work_size=1;
size_t local_work_size=1;
size_t string_len;

void load_source()
{
	FILE *fp;
    fp = fopen("sha1.cl", "r");
	if (!fp) {
		fprintf(stderr, "Failed to load kernel.\n");
		exit(1);
	}
	source_str = (char*)malloc(MAX_SOURCE_SIZE);
	source_size = fread( source_str, 1, MAX_SOURCE_SIZE, fp);
	fclose( fp );
}

void set_key(char *key, int index){
	memcpy(&(saved_plain[index*PLAINTEXT_LENGTH]), key, PLAINTEXT_LENGTH);
	datai[0] = PLAINTEXT_LENGTH;
	datai[1] = global_work_size;
}

void sha1(char* str) {
	string_len = strlen(str);
	global_work_size = 1;
	datai[0] = PLAINTEXT_LENGTH;
	datai[1] = global_work_size;
	datai[2] = string_len;
	memcpy(saved_plain, str, string_len);
}

void create_clobj(int kpc){
	pinned_saved_keys = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (PLAINTEXT_LENGTH)*kpc, NULL, &ret);
	saved_plain = (char*)clEnqueueMapBuffer(command_queue, pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (PLAINTEXT_LENGTH)*kpc, 0, NULL, NULL, &ret);
	memset(saved_plain, 0, PLAINTEXT_LENGTH * kpc);
	res_hashes = (cl_uint *)malloc(sizeof(cl_uint) * 4 * kpc);
	memset(res_hashes, 0, sizeof(cl_uint) * 4 * kpc);
	pinned_partial_hashes = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret);
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(command_queue, pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret);
	memset(partial_hashes, 0, sizeof(cl_uint) * kpc);

	buffer_keys = clCreateBuffer(context, CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH) * kpc, NULL, &ret);
	buffer_out = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 5 * kpc, NULL, &ret);
	data_info = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int) * 3, NULL, &ret);

	clSetKernelArg(kernel, 0, sizeof(data_info), (void *) &data_info);
	clSetKernelArg(kernel, 1, sizeof(buffer_keys), (void *) &buffer_keys);
	clSetKernelArg(kernel, 2, sizeof(buffer_out), (void *) &buffer_out);

    sha1("gbcHqTYxBWjOecmSYutcoDyiMTpgVjUCSqEoucgjDiVNmXuowGkIbpwmYWdWLkpv\x17W\x1e\x08");
}

void create_clobj(void){
	int optimal_kpc=2048;
	create_clobj(optimal_kpc);
}

void printf_result()
{
	//
	int i;
	for (i=0;i<5;i++)
	{
		printf("partial_hashes[%d]: %u\n", i, partial_hashes[i]);
	}

	for(i=0; i<5; i++)
	{
		printf("%08x", partial_hashes[i]);
		
	}
	printf("\n");
}

void crypt_all()
{
    ret = clEnqueueWriteBuffer(command_queue, data_info,
                               CL_TRUE, 0, sizeof(unsigned int) * 3, datai, 0, NULL, NULL);

    ret = clEnqueueWriteBuffer(command_queue, buffer_keys,
                               CL_TRUE, 0, PLAINTEXT_LENGTH * kpc, saved_plain, 0, NULL, NULL);

    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1,
                               NULL, &global_work_size, &local_work_size, 0, NULL, NULL);

    ret = clFinish(command_queue);

    ret = clEnqueueReadBuffer(command_queue, buffer_out,
                              CL_TRUE, 0, sizeof(cl_uint) * global_work_size * 5, partial_hashes, 0, NULL, NULL);

    ret = clEnqueueReadBuffer(command_queue, buffer_keys,
                              CL_TRUE, 0, 63, saved_plain, 0, NULL, NULL);

    have_full_hashes = 0;
}

int main()
{
	ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
	ret = clGetDeviceIDs( platform_id, CL_DEVICE_TYPE_ALL, 1, &device_id, &ret_num_devices);

    std::cerr << " === "
              << " d:" << ret_num_devices
              << " p:" << ret_num_platforms << std::endl;

    context = clCreateContext( NULL, 1, &device_id, NULL, NULL, &ret);
	load_source();
	program = clCreateProgramWithSource(context, 1, (const char **)&source_str, (const size_t *)&source_size, &ret);


	ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
    std::cerr << "build " << ret << std::endl;

    if(ret != CL_SUCCESS) {
        char* build_log;
        size_t log_size;
        // First call to know the proper size
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        build_log = new char[log_size+1];
        // Second call to get the log
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, log_size, build_log, nullptr);
        build_log[log_size] = '\0';
        std::cout << " --- " << build_log << std::endl;
        delete[] build_log;
        ::exit(1);
    }

    kernel = clCreateKernel(program, "sha1_multi", &ret);
    std::cerr << "program " << program << " KERNEL " << kernel << " " << ret << std::endl;
    command_queue = clCreateCommandQueue(context, device_id, 0, &ret);

    time_t t0 = ::time(nullptr);

    for(int i=0;i<256;i++) {
        create_clobj();
        std::cerr << "A '" << std::string(saved_plain,PLAINTEXT_LENGTH) << "'" << std::endl;
        crypt_all();
        std::cerr << "B '" << std::string(saved_plain,PLAINTEXT_LENGTH) << "'" << std::endl;
        
        std::string oo(saved_plain,PLAINTEXT_LENGTH);
        std::cerr << "'";
        for(const auto & c : oo) {
            if(c<32)
                std::cerr << "\\x" << std::hex << std::setfill('0') << std::setw(2) 
                          << ((unsigned int)c & 0xff) << std::dec;
            else
                std::cerr << c;
        }
        std::cerr << "'" << std::endl;;
    }
    std::cerr << " sT==" << ::time(nullptr) - t0 << std::endl;

    for( int i=0;i<5;i++) {
        std::cerr << std::hex << std::setw(8) << std::setfill('0')
                  << (uint32_t)partial_hashes[i];
    }
    std::cerr << std::endl;

}
