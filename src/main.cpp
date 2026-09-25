#include <iostream>
#include "../include/names.h"

int main(){
    ETWconsumer::start();

    if (Blasphemy.joinable())
    {
        Blasphemy.join();
    }
    
    if (Truth.joinable())
    {
        Truth.join();
    }
}