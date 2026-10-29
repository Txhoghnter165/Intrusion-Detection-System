#pragma once
#include <thread>
#include "../ETW_consumer/krabs/krabs.hpp"

struct ETWconsumer
{
   static void start();
};
struct test_001
{
   static void start();
};
struct Security_Filter
{
   static void start(krabs::schema& schema);
};
extern std::thread Truth;
extern std::thread Blasphemy;