#pragma once
#include <thread>
struct ETWconsumer
{
   static void start();
};
struct test_001
{
   static void start();
};

extern std::thread Truth;
extern std::thread Blasphemy;