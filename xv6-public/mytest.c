#include "types.h"
#include "user.h"
#include "stat.h"

int main(){
	int i;
	for(i = 1; i < 11; ++i){
		printf(1, "%d %d\n", i, setnice(i, 5));
	}
	exit();
}
		
