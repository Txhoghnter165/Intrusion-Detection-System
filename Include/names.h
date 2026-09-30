#pragma once
#include <thread>
struct ETWconsumer
{
   static void start();
};

extern std::thread Truth;
extern std::thread Blasphemy;