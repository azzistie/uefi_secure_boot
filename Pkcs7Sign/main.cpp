/*
该文件为验签文件
只需传入一个签名文件参数，公钥文件在代码中默认指定 signing_key.x509

*/


#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>

#include <arpa/inet.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;




void read_bytes(const char* fname, vector<char>& buffer) {
  buffer.clear();
  ifstream fin(fname, ios::binary | ios::in);

  if (!fin) return;

  fin.seekg(0, fin.end);
  size_t length = fin.tellg();
  fin.seekg(0, fin.beg);

  if (length > 0) {
    buffer.resize(length);
    fin.read(&buffer[0], length);
  }
}



void Byte2Hex(unsigned char byte, char *res){
	//efi_printk(sys_table, "tag2\n");
	char binaries[8];
	int index = 0;
	res[0] = res[1] = '0';
	int base[4] = {1, 2, 4, 8};
	
	
	while(index < 8){
		//efi_printk(sys_table, "tag3\n");
		binaries[index++] = byte%2;
		byte /= 2;
	}
	
	for(int i = 0; i < 4; i++){
		//efi_printk(sys_table, "tag4\n");
		res[1] += binaries[i] * base[i];
		res[0] += binaries[i + 4] * base[i];
	}
	
	if(res[0] > '9') res[0] = res[0] - '9' + 'A' - 1;
	if(res[1] > '9') res[1] = res[1] - '9' + 'A' - 1;

}

//输入一个16字节的数组，转换为十六进制字符形式
//num长度16，res长度为33
void string16(char *num, char *res){
	
	//Print(L"In protocol, the func accessmem revoked string16...\n");
	
	char temp[2];
	
	for(int i=0,j=15;i<16;i++,j--){
		
		Byte2Hex(num[i],temp);
		
		res[j*2] = temp[0];
		res[j*2+1] = temp[1];
		
	}
	
	res[32]='\n';
	res[33]=0;
	
}



int main(int argc, char **argv) {
  vector<char> fw_buffer;
  vector<char> cert_buffer;
  size_t fw_size, sig_len, data_len;
  char* fw_buffer_ptr = NULL;
  char* sig_buffer_ptr = NULL;
  BIO *cms_bio = NULL, *cert_bio = NULL, *data_bio;
  CMS_ContentInfo* cms = NULL;
  X509* cert;
  X509_STORE* st = NULL;
  unsigned long err_code;
  STACK_OF(X509) * stack;
  unsigned long* sig_len_ptr = NULL;

  OpenSSL_add_all_digests();
  if(argc < 2) {
      cout << "Usage: scripts/main [filename]" << endl;
      return 0;
  }
  
  read_bytes(argv[1], fw_buffer);
  fw_size = fw_buffer.size();
  cout << "Read " << fw_size << " bytes from " << argv[1] << endl;

  fw_buffer_ptr = fw_buffer.data();

  if (fw_size < sizeof(unsigned long)) {
    cout << "The size of " << argv[1] << " abc is too small.\n";
    goto out;
  }
  // point to signature len
  // unsigned long* sig_len_ptr;
  //传入文件的最后一个存储块（尺寸、大小端不明）为签名的尺寸
  sig_len_ptr = reinterpret_cast<unsigned long*>(fw_buffer_ptr + fw_size -
                                                sizeof(unsigned long));
												
  fw_size -= sizeof(sig_len_ptr);//文件总尺寸需要减去最后存储尺寸的内存块
  sig_len = *sig_len_ptr;

  if (fw_size < sig_len) {
    cout << "The size of " << argv[1] << " efjk is too small.\n";
    goto out;
  }

  data_len = fw_size - sig_len;

  cout << "Size of data: " << data_len << endl;
  cout << "Size of signature: " << sig_len << endl;

  sig_buffer_ptr = fw_buffer_ptr + data_len;

//解析完成

  cms_bio = BIO_new(BIO_s_mem());
  if (cms_bio == NULL) {
    cout << "Unable to create BIO for CMS.\n";
    goto out;
  }
  if (BIO_write(cms_bio, sig_buffer_ptr, sig_len) <= 0) {
    cout << "Unable to write CMS buffer to BIO.\n";
    goto out;
  }
  cms = d2i_CMS_bio(cms_bio, NULL);
  if (cms == NULL) {
    cout << "Unable to transform CMS content info.\n";
    goto out;
  }
  
//读取公钥  
  read_bytes("signing_key.x509", cert_buffer);
  if (cert_buffer.size() <= 0) {
    cout << "The size of signing_key.x509 is too small.\n";
    goto out;
  }

  cert_bio = BIO_new(BIO_s_mem());
  if (cert_bio == NULL) {
    cout << "Unable to create BIO for CERT.\n";
    goto out;
  }
  if (BIO_write(cert_bio, cert_buffer.data(), cert_buffer.size()) <= 0) {
    cout << "Unable to write CERT buffer to BIO.\n";
    goto out;
  }
  cert = d2i_X509_bio(cert_bio, NULL);
  if (cert == NULL) {
    cout << "Unable to transform CMS content info.\n";
    goto out;
  }

  st = X509_STORE_new();
  if (st == NULL) {
    cout << "Unable to create cert store.\n";
    goto out;
  }

  if (!(X509_STORE_add_cert(st, cert))) {
    cout << "Unable to add cert to store.\n";
    goto out;
  }

  data_bio = BIO_new(BIO_s_mem());
  if (data_bio == NULL) {
    cout << "Unable to create BIO for data.\n";
    goto out;
  }
  if (BIO_write(data_bio, fw_buffer_ptr, data_len) <= 0) {
    cout << "Unable to write data buffer to BIO.\n";
    goto out;
  }

  if ((stack = sk_X509_new_null()) == NULL) {
    cout << "Unable to create X509 stack.\n";
    goto out;
  }
  if (sk_X509_push(stack, cert) == 0) {
    cout << "Unable to push X509 to stack.\n";
    goto out;
  }
	/*
	char res[40];
	
	string16((char*)st,res);
	printf("%s",res);
	
	string16((char*)st+16,res);
	printf("%s",res);
	
	string16((char*)st+32,res);
	printf("%s",res);
	
	string16((char*)st+48,res);
	printf("%s",res);
	
	string16((char*)st+64,res);
	printf("%s",res);
	
	printf("------------\n");
	
	
	string16((char*)stack,res);
	printf("%s",res);
	
	string16((char*)stack+16,res);
	printf("%s",res);
	
	string16((char*)stack+32,res);
	printf("%s",res);
	
	string16((char*)stack+48,res);
	printf("%s",res);
	
	string16((char*)stack+64,res);
	printf("%s",res);
	
	printf("------------\n");
	
	
	string16((char*)stack,res);
	printf("%s",res);
	
	string16((char*)stack+16,res);
	printf("%s",res);
	
	string16((char*)stack+32,res);
	printf("%s",res);
	
	string16((char*)stack+48,res);
	printf("%s",res);
	
	string16((char*)stack+64,res);
	printf("%s",res);
	
	printf("------------\n");
	
	
	string16((char*)data_bio,res);
	printf("%s",res);
	
	string16((char*)data_bio+16,res);
	printf("%s",res);
	
	string16((char*)data_bio+32,res);
	printf("%s",res);
	
	string16((char*)data_bio+48,res);
	printf("%s",res);
	
	string16((char*)data_bio+64,res);
	printf("%s",res);
	
	
	printf("------------\n");
	
	
	string16((char*)cms,res);
	printf("%s",res);
	
	string16((char*)cms+16,res);
	printf("%s",res);
	
	string16((char*)cms+32,res);
	printf("%s",res);
	
	string16((char*)cms+48,res);
	printf("%s",res);
	
	string16((char*)cms+64,res);
	printf("%s",res);
	
	printf("------------\n");
	
	int a[20]={1,2,3,4,5,6,7,8,9,10};
	string16((char*)a,res);
	printf("%s",res);
	string16((char*)a+16,res);
	printf("%s",res);
	*/
	
	
	
  if (!CMS_verify(cms, stack, st, data_bio, NULL,
                  CMS_NOINTERN | CMS_BINARY |CMS_NO_SIGNER_CERT_VERIFY)) {
    cout << "Verification failure.\n";
  } else {
    cout << "Verification successful.\n";
  }

  err_code = ERR_get_error();
  if (err_code != 0) {
    cout << ERR_error_string(err_code, NULL) << endl;
  }

out:
  // if (pkey != NULL) EVP_PKEY_free(pkey);
  if (cms != NULL) CMS_ContentInfo_free(cms);
  if (cert != NULL) X509_free(cert);
  if (st != NULL) X509_STORE_free(st);
  if (cms_bio != NULL) BIO_free(cms_bio);
  if (cert_bio != NULL) BIO_free(cert_bio);
  if (data_bio != NULL) BIO_free(data_bio);
  return 0;
}
