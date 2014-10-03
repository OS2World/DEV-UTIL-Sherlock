

/****************************/
/* Defining the Base Class  */
/****************************/

class _Export area
   {
   private:
      double dim1, dim2;
   public:
      static int   objectCount;
      void setarea(double d1 , double d2);
      void getdim(double &d1, double &d2);
      virtual double getarea();
      area::area(void);
   };


/*******************************/
/* Defining a   Derived class  */
/*******************************/


class _Export rectangle : public area
   {
   public:
      static int objectCount ;
      double getarea();
      rectangle::rectangle(void);
   };

/*******************************/
/* Defining a   Derived class  */
/*******************************/


class _Export triangle : public area
   {
   public:
      static int objectCount;
      double getarea();
      triangle::triangle(void);
   };


