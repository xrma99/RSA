#include <gmpxx.h>
#include <iostream>
#include <stdio.h>
#include <fstream>
#include <string.h>

#define IFINITY 999

using namespace std;

int charToint(char c){
	if(c<='9'&&c>='0'){
		return c-'0';
	}else if(c<='z'&&c>='a'){
		return c-'a'+10;
	}else if(c<='Z'&&c>='A'){
		return c-'A'+36;
	}
	return -1;

}

void intTochar(mpz_t x,int flag){
	ofstream outfile;
	if(flag==1) outfile.open("plaintext2.txt",ios::app);
	else if(flag==2) outfile.open("plaintext3.txt",ios::app);
	else return;
	mpz_t tmp[26];
	int i;
	char c;
	for(i=0;i<26;i++){
		mpz_init_set_ui(tmp[i],i);
	}
	if(mpz_cmp_ui(x,10)<0){//0~9
		for(i=0;i<10;i++){
			if(mpz_cmp(x,tmp[i])==0){
				outfile<<i;
				break;
			}
		}
	}else if(mpz_cmp_ui(x,36)<0){//a~z
		mpz_sub_ui(x,x,10);
		for(i=0;i<26;i++){
			if(mpz_cmp(x,tmp[i])==0){
				c=i+'a';
				outfile<<c;
				break;
			}
		}
	}else{//A~Z
		mpz_sub_ui(x,x,36);
		for(i=0;i<26;i++){
			if(mpz_cmp(x,tmp[i])==0){
				c=i+'A';
				outfile<<c;
				break;
			}
		}
	}

	for(i=0;i<26;i++){
		mpz_clear(tmp[i]);
	}

}

int main(){
	gmp_randstate_t grt;
	gmp_randinit_default(grt);
	gmp_randseed_ui(grt,time(NULL));

	mpz_t p,q;
	mpz_init(p);
	mpz_init(q);

	mpz_urandomb(p,grt,128);//pick up p ranged in 0~2^128
	mpz_urandomb(q,grt,128);

	mpz_nextprime(p,p);//select the next prime number larger than p and store the value back to p
	mpz_nextprime(q,q);
	gmp_printf("Prime Number p:%ZX\n\n",p);
	gmp_printf("Prime Number q:%ZX\n\n",q);

	mpz_t n;
	mpz_init(n);
	mpz_mul(n,p,q);
	gmp_printf("n: %ZX\n\n",n);

	mpz_t fin;//(p-1)*(q-1)
	mpz_init(fin);
	mpz_sub_ui(p,p,1);//ui means number that is not big
	mpz_sub_ui(q,q,1);
	mpz_mul(fin,p,q);
	gmp_printf("fin: %ZX\n\n",fin);

	mpz_t e;
	mpz_init_set_ui(e,30347);
	gmp_printf("Public Key e:%Zd\n\n",e);

	mpz_t d;
	mpz_init(d);
	mpz_invert(d,e,fin);
	gmp_printf("Private Key d:%ZX\n\n",d);

	//Clear the plaintext2.txt
	ofstream outfile("plaintext2.txt");
	if(!outfile.is_open())return -1;
	outfile.close();

	char tmp[2];
	int data[2]={-1,-1};
	int i;
	mpz_t M,C,M2;
	mpz_init(M);
	mpz_init(C);
	mpz_init(M2);

	mpz_t x;
	mpz_init(x);

	ifstream infile("plaintext.txt");
	if(!infile.is_open())return -1;

	gmp_printf("Encrypted with e:\n");

	while(!infile.eof()){
		
		i=0;
		while (data[0]==-1&&i<IFINITY){
			infile>>tmp[0];
			data[0]=charToint(tmp[0]);
			i++;
		}
		if(i==IFINITY) break;

		
		i=0;
		while (data[1]==-1&&i<IFINITY){
			infile>>tmp[1];
			data[1]=charToint(tmp[1]);
			i++;
		}
		if(i==IFINITY) break;

		mpz_set_ui(M,data[0]*100+data[1]);

		mpz_powm(C,M,e,n);//Encryption
		gmp_printf("%ZX\n",C);
		mpz_powm(M2,C,d,n);//Decryption

		mpz_fdiv_q_ui(x,M2,100);
		intTochar(x,1);
				
		mpz_fdiv_r_ui(x,M2,100);
		intTochar(x,1);
		
		data[0]=data[1]=-1;

	}

	infile.close();

	ofstream outfile2("plaintext3.txt");
	if(!outfile2.is_open())return -1;
	outfile2.close();

	ifstream infile2("plaintext.txt");
	if(!infile2.is_open())return -1;

	gmp_printf("\nEncrypted with d:\n");

	data[0]=data[1]=-1;
	while(!infile2.eof()){
		
		i=0;
		while (data[0]==-1&&i<IFINITY){
			infile2>>tmp[0];
			data[0]=charToint(tmp[0]);
			i++;
		}
		if(i==IFINITY) break;

		
		i=0;
		while (data[1]==-1&&i<IFINITY){
			infile2>>tmp[1];
			data[1]=charToint(tmp[1]);
			i++;
		}
		if(i==IFINITY) break;

		mpz_set_ui(M,data[0]*100+data[1]);

		mpz_powm(C,M,d,n);//Encryption
		gmp_printf("%ZX\n",C);
		mpz_powm(M2,C,e,n);//Decryption

		mpz_fdiv_q_ui(x,M2,100);
		intTochar(x,2);
				
		mpz_fdiv_r_ui(x,M2,100);
		intTochar(x,2);
		
		data[0]=data[1]=-1;

	}

	infile2.close();

	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(fin);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(M);
	mpz_clear(C);
	mpz_clear(M2);
	mpz_clear(x);

/*
	mpz_t a,b,c;
	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
	gmp_scanf("%Zd%Zd",a,b);
	mpz_add(c,a,b);
	gmp_printf("c=%Zd\n",c);
	*/
	return 0;
}