#include "types.h"
#include "user.h"
#include "stat.h"

int main(){
	int i, j, k;
	setnice(1, 5);
	setnice(2,5);
	setnice(getpid(),5);
	if(fork() == 0){
		setnice(getpid(), 0);
		for(i = 0; i < 2000000000; ++i){
			for(j = 0; j < 1000000000; ++j){
				for(k = 0; k < 1000000000; ++k){
					ps(0);
				}
			}
		}
		ps(0);
	}
	else{
		for(i = 0; i < 2000000000; ++i){
			for(j = 0; j < 1000000000; ++j){
				for(k = 0; k < 1000000000; ++k){
					ps(0);
				}
			}
		}
		wait();
		ps(0);
	}	
	exit();
}
		
