#include <iostream.h>
#include <assert.h>
#include "vf.h"

int main(void)
   {
   rectangle r1,r2;    // Creates two objects
   triangle  t1;

   cout << "\n\n" ;
   cout << "Number of rectangles created " << rectangle::objectCount << '\n';
   cout << "Number of triangles created " << triangle::objectCount << '\n';
   cout << "Number of base objects " << area::objectCount << "\n\n";

   cout << "Setting dimensions of rectangle to be  2.5 x 2. \n";
   r1.setarea(2.5,2);

   cout << "Setting dimensions of triangle to be base=4, height=2 \n";
   t1.setarea(4,2);

   cout << "Area of rectangle is " << r1.getarea() << '\n' ;
   cout << "Area of triangle is " << t1.getarea() << "\n\n" ;

   cout << "Program terminates";
   return 0;
   }
