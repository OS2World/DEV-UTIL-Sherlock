/*
** Main entrance routine.
*/
#include    <stdio.h>

struct _tag {
    short   a;
    int     b;
    float   c;
    double  d;
} e[2] = {{2, 4, 8.0, 20.0}, {12, 14, 18.10, 120.0}};

int func(short a, int b, float c, double d, struct _tag *f);
int func(short a, int b, float c, double d, struct _tag *f)
{
    a = 10;
    b = 20;
    c = 40;
    d = 60;
    f->a = 210;
    f->b = 220;
    f->c = 230;
    f->d = 240;
    return 10;
}

int This_is_a_Long_function_name_to_test_the_name_limit_imposed_by_the_Record_format_This_is_a_Long_function_name_to_test_the_name_limit_imposed_by_the_Record_format_()
{
int *ptr = NULL;

    return *ptr;

}


int main(int argc, char **argv);
int main(int argc, char **argv)
{
int	b = 2;
#if 0
short	a = 1;
float	c = 3.1;
double	d = 12.3;

    func(a, b, c, d, &e[0]);
#endif
    b = This_is_a_Long_function_name_to_test_the_name_limit_imposed_by_the_Record_format_This_is_a_Long_function_name_to_test_the_name_limit_imposed_by_the_Record_format_();
    while(1)
	;
    return 1;
}
