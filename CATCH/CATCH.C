/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/

/*
** Main entrance routine.
*/
#define INCL_DOSDATETIME
#include <os2.h>

APIRET _System DosSleep(ULONG time);

int main(int argc, char **argv);
int main(int argc, char **argv)
{
    DosSleep(10000);
    DosOpen((PSZ)    0,     /* pszFileName */
	    (PHFILE) 0,     /* pHf	   */
	    (PULONG) 0,     /* pulAction   */
		     0,     /* cbFile	   */
		     0,     /* ulAttribute */
		     0,     /* fsOpenFlags */
		     0,     /* fsOpenMode  */
	    (PEAOP2) 0);    /* peaop2	   */
    return 0;
}
