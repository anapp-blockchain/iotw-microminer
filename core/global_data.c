#include <string.h>
#include "global_data.h"

volatile struct gdata gdat = {0,};
volatile struct gdata * gd = &gdat;

int32_t gdata_init(void){
	return 0;
}

