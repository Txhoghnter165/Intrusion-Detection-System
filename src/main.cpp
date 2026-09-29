#include <iostream>
#include "../include/names.h"
#include <thread>
int main(){
    ETWconsumer::start();
std::this_thread::sleep_for(std::chrono::seconds(120));
   if (Blasphemy.joinable())
    {
        Blasphemy.join();
    }
    
    if (Truth.joinable())
    {
        Truth.join();
    } 
} 