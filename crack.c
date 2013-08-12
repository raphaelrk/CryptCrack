/* accepts a single encrypted password
 * crack it, output it and write \n
 * 
 * notes:
 * password uses crpyt()
 *   takes a password string and a salt character array
 *   returns ASCII string beginning with a salt character array
 *   salt decides MD5 or DES and makes cracking harder
 *   for MD5 salt has string $1$, followed by up to 8 characters,
 *    terminated by$ or /0
 *    result will be salt and $, then 22 characters a-z,A-z,0-9 
 *    up to 34 characters total
 *   ..But pset uses DES encryption
 * 
 */
 
 
#include <stdio.h>
 #include <string.h>
 #include <time.h>
 #include <math.h>
 #include <stdlib.h>
 #define UINT_MAX 4294967295
 
 #define _XOPEN_SOURCE
 #include <unistd.h>
 #include <crypt.h>
 
 char * brutemenu(void);
 
 int bruterecursion(int value, int level, char * passtry, char * salt, char * encrypted, int symbols);
 
 int obvious(char * salt, char * encrypted);
 
 int checkcrypt(char * passtry, char * salt, char * encrypted);
 
 int ochartry(int number);
 
 char * GetString(void);
 
 int
 main(int argc, char * argv[])
 {
    //this first part just checks your command-line input
    if (argc != 2)
    {
        printf("Give me a contiguous password\n");
        return 1;
    }

    int paslen = strlen(argv[1]);

    if (paslen > 13)
    {
        printf("Too long of a password");
        return 1;
    }

    //This part creates the variables/pointers that'll be used throughout the program
    //Specifically:
    //    It opens a dictionary file on my computer
    //    It  renames the command-line input
    //    It creates arrays and pointers to them (maybe that's a little much?)
    //    "salt" is the first two letters of the ciphertext and is like a seed using in crypt()
    //    cycle and checkpass are used in the loops, cycle was mainly for bugchecking
    FILE * dictionary;
    char * encrypted = argv[1];
    char parray[20];
    for (int i = 0; i < 15; i++)
        parray[i] = '\0';
    char * passtry = parray;
    char sarray[3];
    char * salt = sarray; 
    sarray[0] = encrypted[0]; sarray[1] = encrypted[1]; sarray[2] = '\0'; 
    int cycle = 0;
    int checkpass = 0;
    
    char * choose = brutemenu(); // function to choose your password attack
    
    //This part goes to obvious() and returns 1 if it succeeds in finding the password
    printf("trying common passwords\n");
    checkpass = obvious(salt, encrypted); //try some common passwords
    if (checkpass == 1)
    {
        fclose(dictionary); 
        return 0;
    }
    
   if (choose[0] == '1')
   {
    //This part tries the dictionary
    dictionary = fopen("/usr/share/dict/words", "r"); // open dictionary
    if (!dictionary) // check if fopen fails
    {
        printf("No dictionary.\n");
        return 2;
    }
    printf("trying dictionary words\n");
    while (feof(dictionary) == 0) //try the dictionary as a pass
    {
        fgets(passtry, 20, dictionary);
        int passtrylen = strlen(passtry);
        for (int i = (passtrylen <= 8) ? passtrylen - 1: 8 ; i < 21; i++)
            parray[i] = '\0';
        if (cycle % 5000 == 1)
            printf("passtry: %s\n", passtry);
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            fclose(dictionary);
            return 0;
        }
        cycle += 1;
    }
    fclose(dictionary);
   }
   
   if (choose[1] == '1')
   {
    printf("Going to numbers\n");
    sleep(1);
    int incycle = 0;
    int numlen = 1;
    
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
    
    
    for(cycle = 0; cycle < 100000000; cycle++) //try numbers as passes
    {
        if (cycle % 10000 == 1)
            printf("passtry: %s\n", passtry);
        if (cycle > 0)
            numlen = floor(log10(cycle)) +1;
        incycle = cycle;
        for (int i = 0, len = numlen; i < len; i++)   
        { 
            int numneeded = floor(incycle / pow(10, numlen - 1));
            parray[i] = (char) numneeded + 48;
            incycle -= numneeded*pow(10, numlen - 1);
            numlen -= 1;
        }
        
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS \n%s\n", passtry);
            return 0;
        }
    }
   }
    
    if (choose[2] == '1')
    {
        printf("Bruteforce beginning.\n");
        sleep(1);
        int symbols = (choose[3] == '1');
        //printf("Would you like to include symbols? (1) for yes ");
        //scanf("%i", &symbols);
        if (symbols == 1)
            symbols = 78;
        else
            symbols = 62;
        
        for (int i = 0; i < 20; i++)
            parray[i] = '\0';
        
        for(int i = 0; i < 8; i++)
        {
            int check = bruterecursion(i, 0, passtry, salt, encrypted, symbols);
            if (check == 1)
                return 0;
        }   
    }
    
    
    printf("UNABLE TO FIND PASSWORD\n");
 }
 
 char * brutemenu(void)
 {
    static char chosen[5];
    chosen[0] = '0'; chosen[1] = '0'; chosen[2] = '0'; chosen[3] = '0'; chosen[4] = '\0';
    
    printf("Would you like to dictionary attack? (y for yes) ");
    char * chosen0 = GetString();
    if (chosen0[0] == 'y')
    {
        printf("You have chosen yes!\n");
        chosen[0] = '1';
    }
    
    printf("Would you like to number attack? (y for yes) ");
    char * chosen1 = GetString();
    if (chosen1[0] == 'y')
    {
        printf("You have chosen yes!\n");
        chosen[1] = '1';
    }
    
    printf("Would you like to brute force? (y for yes)");
    char * chosen3 = NULL;
    char * chosen2 = GetString();
    if (chosen2[0] == 'y')
    {
        printf("You have chosen yes!\n");
        chosen[2] = '1';
        printf("Would you like to include symbols in your bruteforce?");
        char * chosen3 = GetString();
        if (chosen3[0] =='y')
        {
            printf("You have chosen yes!\n");
            chosen[3] = 1;
        }
    }
    
    free(chosen0);free(chosen1);free(chosen2);free(chosen3);
    
    char * ret = chosen;
    return ret;
 }
 
 int bruterecursion(int value, int level, char * passtry, char * salt, char * encrypted, int symbols)
 {
    int brutereturn = 0;
    int cycle = 0;
    
    for (int a = 0; a < symbols; a++)
    {
        
        int chartry = ochartry(a);
        passtry[level] = (char) chartry;
                    
        if (value > 0)
        {
            value -= 1;
            level += 1;
            brutereturn = bruterecursion(value, level, passtry, salt, encrypted, symbols);
            if (brutereturn == 1)
                return 1;
            value += 1;
            level -= 1;
        }
        if (cycle % 1618 == 1)
            printf("passtry: %s\n", passtry);            
        int checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS \n%s\n", passtry);
            return 1;
        }
        cycle++;
    }
    return 0;
 }
 
 int ochartry(int number) //returns char number for brute force
 {
    if (number < 26)
        return number + 97;//lowercase
    else if (number < 52)
        return number - 26 + 65;
    else if (number < 62)
        return number - 52 + 48;
    else if (number < 68)
        return number - 62 + 42;
    else if (number < 70)
        return number - 68 + 63;
    else if (number < 75)
        return number - 70 + 91;
    else if (number < 76)
        return number - 75 + 123;
    else if (number < 78)
        return number - 76 + 125;
        
    return -1;
 }
 
 int obvious(char * salt, char * encrypted) //try common passwords
 {
    int checkpass = 0;
    char parray[20];
    char * passtry = parray;
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
    
    for(int j = 0; j < 8; j++) // tries ascending lowercase letters
    {
        parray[j] = (char) j + 97;
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            return 1;
        }
    }
    
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
    
    for (int j = 0; j < 8; j++) // tries ascending capital letters
    {
        parray[j] = (char) j + 65;
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            return 1;
        }
    }
    
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
        
    for (int j = 0; j < 8; j++) // tries ascending numbers
    {
        parray[j] = (char) j + 1 + 48;
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            return 1;
        }
    }
    
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
    
    for (int j = 0; j < 8; j++) // tries descending numbers
    {
        parray[j] = (char) 9 - j + 48;
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            return 1;
        }	
    
    }
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
    
    for (int j = 0; j < 4; j++) // tries 123abc passwords
    {
        parray[j] = '1' + j;
        for (int k = 1; k < j+2; k++)
        {
            parray[k + j] = 'a' + k - 1;
        }
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            return 1;
        }
    }
    for (int i = 0; i < 20; i++)
        parray[i] = '\0';
        
    for (int j = 0; j < 4; j++) // tries abc123 passwords
    {
        parray[j] = 'a' + j;
        for (int k = 1; k < j+2; k++)
        {
            parray[k + j] = '0' + k;
        }
        
        checkpass = checkcrypt(passtry, salt, encrypted);
        if (checkpass == 1)
        {
            printf("PASSWORD IS: \n%s\n", passtry);
            return 1;
        }
    }
        
    return 0;
 }
 
 
 int checkcrypt(char * password, char *salt, char * encrypted)
 {
    char * returned = crypt(password, salt);
    
    if (returned[2] == encrypted[2])
    {
        int compare = strcmp(returned, encrypted);
        if (compare == 0)
        {
            return 1;
        }
    }
    return 0;
 }
 
char * GetString(void) //From cs50 library
{
    // growable buffer for chars
    char * buffer = NULL;

    // capacity of buffer
    unsigned int capacity = 0;

    // number of chars actually in buffer
    unsigned int n = 0;

    // character read or EOF
    int c;

    // iteratively get chars from standard input
    while ((c = fgetc(stdin)) != '\n' && c != EOF)
    {
        // grow buffer if necessary
        if (n + 1 > capacity)
        {
            // determine new capacity: start at 32 then double
            if (capacity == 0)
                capacity = 32;
            else if (capacity <= (UINT_MAX / 2))
                capacity *= 2;
            else
            {
                free(buffer);
                return NULL;
            }

            // extend buffer's capacity
            char * temp = realloc(buffer, capacity * sizeof(char));
            if (temp == NULL)
            {
                free(buffer);
                return NULL;
            }
            buffer = temp;
        }

        // append current character to buffer
        buffer[n++] = c;
    }

    // return NULL if user provided no input
    if (n == 0 && c == EOF)
        return NULL;

    // minimize buffer
    char * minimal = malloc((n + 1) * sizeof(char));
    strncpy(minimal, buffer, n);
    free(buffer);

    // terminate string
    minimal[n] = '\0';

    // return string
    return minimal;
}
 
 
