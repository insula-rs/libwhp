#include <stdint.h>

uint32_t itoa(int value, char str[]){
    char const char_digit[] = "0123456789";
    char* p = str;
    int len = 0;
    int temp_value;

    if (value < 0) {
        *p++ = '-';
        value *= -1;
    }

    temp_value = value;

    do {
        len++;
        ++p;
        temp_value = temp_value / 10;
    } while (temp_value);

    *p = '\0';

    do {
        *--p = char_digit[value % 10];
        value = value / 10;
    } while (value);

    return len;
}
