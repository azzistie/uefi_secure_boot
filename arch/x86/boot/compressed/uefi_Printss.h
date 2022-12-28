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

void string4(char *num, char *res){
	
	//efi_printk(sys_table, "tag1\n");
	
	char temp[2];
	for(int i=0;i<4;i++){
		
		Byte2Hex(num[i],temp);
		//efi_printk(sys_table, "tag5\n");
		res[i*2] = temp[0];
		res[i*2+1] = temp[1];
		
	}
	res[8]=0;
	
}

//输入一个16字节的数组，转换为十六进制字符形式
//num长度16，res长度为33
void string16(char *num, char *res){
	
	//Print(L"In protocol, the func accessmem revoked string16...\n");
	
	char temp[2];
	for(int i=0;i<16;i++){
		
		Byte2Hex(num[i],temp);
		//efi_printk(sys_table, "tag5\n");
		res[i*2] = temp[0];
		res[i*2+1] = temp[1];
		
	}
	res[32]='\n';
	res[33]=0;
	
}

void string8(char *num, char *res){
	
	//Print(L"In protocol, the func accessmem revoked string8...\n");
	
	char temp[2];
	for(int i=0;i<8;i++){
		
		Byte2Hex(num[i],temp);
		//efi_printk(sys_table, "tag5\n");
		res[i*2] = temp[0];
		res[i*2+1] = temp[1];
		
	}
	res[16]='\n';
	res[17]=0;
	
}


//打印char8*普通类型的字符串
//传入参数为普通类型的字符串，以0结尾以判断结束
/*void char8tochar16(char *str)
{
	char *s8;

	for (s8 = str; *s8; s8++) {
		
		CHAR16 ch[2] = { 0 };

		ch[0] = *s8;
		if (*s8 == '\n') {
			Print(L"\n");
			continue;
		}
		gST->ConOut->OutputString(gST->ConOut, ch);//单字符逐个打印
	}
}*/


void Int64toHex(u64 ptr,char *str){
	
	
	str[16]='\n';
	str[17]=0;
	for(int i=0;i<16;i++) str[i]='0';
	
	int index=15;
	while(index>=0){
		
		int digit=ptr%16;
		ptr=ptr/16;
		
		if(digit>=10) digit=digit-10+'A';
		else digit=digit+'0';
		
		str[index--]=digit;
		
	}
}


u64 Pow(char a,char x){
	if(a==0) return 0;
	if(x==0) return 1;
	u64 r=1;
	for(;x>0;x--){
		r = r * a;
	}
	return r;
}

