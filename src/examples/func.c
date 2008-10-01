// callback function worksheet.

// Since I'm using callback functions a bit different to how I have used them 
// in the past, I need to make sure I can do it properly.


#include <stdio.h>



void apples(int value) 
{
	printf("Apples == %d\n", value);
}


void oranges(char *style) 
{
	printf("oranges are %s\n", style);
}



int main(void) {
	printf("Callback function worksheet\n");
	
	void (*func_a)(int value);
	void (*func_b)(char *style);
	
	void *something[2];
	
	something[0] = &apples;
	something[1] = &oranges;
	
	func_a = something[0];
	func_b = something[1];
	
	(*func_a)(45);
	(*func_b)("happy");
	
	(*something[0])(50);
	
	
	return 0;
}



