#include <thread>
#include <iostream>
#include <cassert>
#include <chrono>
#include "../ETW_consumer/krabs/krabs.hpp"
#include "../Include/names.h"
#include "../include/arraying.h"

    static void configure_security_provider(krabs::provider<>& provider);
    static void configure_registry_provider(krabs::kernel::registry_provider& provider);
    static void configure_file_provider(krabs::kernel::file_io_provider& provider);
    static void configure_network_provider(krabs::provider<>& provider);
    static void configure_process_provider(krabs::kernel::process_provider& provider);

    std::vector <int> numerics = {
        4618,4649,4719,4765,4766,4794,4897,4964,5124,1102,4621,4675,4692,4693,4706,4713,4714,4715,4716,4724,4727,4735,4737,4739,4754,4755,4764,4780,4816,4865,4866,4867,4868,4870,4882,4885,4890,4892,4896,4906,4907,4908,4912,4960,4961,4962,4963,4965,4976,4977,4978,4983,4984,5027,5028,5029,5030,5035,5037,5038,5120,5121,5122,5123,5376,5377,5453,5480,5483,5484,5485,5827,5828,6145,6273,6274,6275,6276,6277,6278,6279,6280,4612,4648,4650,4644,4672,
    };
 void ETWconsumer::start()
{
    /*  krabs::user_trace trace(L"ETWconsumer");
      

      krabs::provider<> Security_provider(krabs::guid(L"{54849625-5478-4994-A5BA-3E3B0328C30D}"));
      krabs::provider<> Registry_provider(krabs::guid(L"{70eb4f03-c1de-4f73-a051-33d13d5413bd}"));
      krabs::provider<> File_provider(krabs::guid(L"{edd08927-9cc4-4e65-b970-c2560fb5c289}"));
      krabs::provider<> Network_provider(krabs::guid(L"{7dd42a49-5329-4832-8dfd-43d979153a88}"));
      krabs::provider<> Process_provider(krabs::guid(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"));


      configure_security_provider(Security_provider);
      configure_registry_provider(Registry_provider);
      configure_file_provider(File_provider);
      configure_network_provider(Network_provider);
      configure_process_provider(Process_provider);

     trace.enable(Security_provider);
     trace.enable(Registry_provider);
     trace.enable(File_provider);
     trace.enable(Network_provider);
     trace.enable(Process_provider);*/
    std::cout << "starting trace user.\n";
    krabs::kernel_trace kernel(L"ETWconsumer");
    krabs::user_trace user(L"ETWconsumer");
    std::cout << "start funtion\n";       
    /*Truth = std::thread([&](){
            try
            {

    std::cout << "Truth start\n";
    std::cout << "this thing is seeing things\n";
      krabs::provider<> Security_provider(krabs::guid(L"{54849625-5478-4994-A5BA-3E3B0328C30D}"));
      krabs::provider<> Registry_provider(krabs::guid(L"{70eb4f03-c1de-4f73-a051-33d13d5413bd}"));
      krabs::provider<> File_provider(krabs::guid(L"{edd08927-9cc4-4e65-b970-c2560fb5c289}"));
      krabs::provider<> Network_provider(krabs::guid(L"{7dd42a49-5329-4832-8dfd-43d979153a88}"));
      krabs::provider<> Process_provider(krabs::guid(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"));
    std::cout << "provider boot\n";

      configure_security_provider(Security_provider);
      configure_registry_provider(Registry_provider);
      configure_file_provider(File_provider);
      configure_network_provider(Network_provider);
      configure_process_provider(Process_provider);
    std::cout << "provider configure\n";
        trace.enable(Security_provider);
        std::cout << "Security enable\n";
        trace.enable(Registry_provider);
        std::cout << "Registry enable\n";
        trace.enable(File_provider);
        std::cout << "File enable\n";
        trace.enable(Network_provider);
        std::cout << "Network enable\n";
        trace.enable(Process_provider);
    std::cout << "providers enabled\n";
        std::cout << "trace start\n";
                trace.start();
                std::cout << "message\n";
            }
            catch (const std::exception& e)
            {
            std::cerr << "Fatal error in trace." << e.what() << std::endl;
         }
    
     });
    */


    krabs::kernel::registry_provider reg;
    krabs::kernel::file_io_provider file;
    krabs::kernel::process_provider process;

    std::cout << "kernel providers loaded\n";

    krabs::provider<> Security_provider(krabs::guid(L"{54849625-5478-4994-A5BA-3E3B0328C30D}"));
    krabs::provider<> Network_provider(krabs::guid(L"{7dd42a49-5329-4832-8dfd-43d979153a88}"));

    std::cout << "user providers loaded\n";

    user.set_enable_provider_error_callback([](const krabs::guid& id, const std::exception& e) {
        
        std::cerr << "Error enabling provider " << id << ": " << e.what() << "\n";
        return true;
    });

    configure_security_provider(Security_provider);
    configure_registry_provider(reg);
    configure_file_provider(file);
    configure_process_provider(process);
    configure_network_provider(Network_provider);

    kernel.enable(reg);
    kernel.enable(file);
    kernel.enable(process);
    std::cout << "kernel providers enabled\n";
    user.enable(Security_provider);
    user.enable(Network_provider);
    std::cout << "user provider enabled\n";

    std::thread forerunner([&]{
        kernel.start();
    });
    std::thread reconciliation([&]{
        user.start();
    });
    std::cout << "kernel and user started\n";

     Blasphemy = std::thread([&]()
     {
        std::cout << "sleep time\n";
std::this_thread::sleep_for(std::chrono::seconds(120));
        kernel.stop();
        std::cout << "kernel stoppped\n";
        user.stop();
        std::cout << "user stoppped\n";
     });

if (forerunner.joinable())
    {
        forerunner.join();
    }
    
if (reconciliation.joinable())
    {
        reconciliation.join();
    }
if (Blasphemy.joinable())
    {
        Blasphemy.join();
    }
}

void configure_security_provider(krabs::provider<>& provider) //Imput all the event IDs you want to monitor for the security provider
{
    provider.any(0xFFFFFFFFFFFFFFFF);

    krabs::event_filter security_filter(
        [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
        {
            krabs::schema schema(record, ctx.schema_locator);
            const auto sid = schema.event_id();
            for (int id : numerics){
                return id == sid;
            }
        });
        provider.add_filter(security_filter);
    security_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx)
    {
         try
        {
            krabs::schema schema(record, ctx.schema_locator);
            if (schema.event_id() == 4624 || schema.event_id() == 4625)
            {
                std::wcout << L"Event 4624 or 4625 received!" << std::endl;
            }
        }
        catch (const std::exception& e) 
        {
            std::cerr << "Error processing event: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown error processing event." << std::endl;
        } 
    });


}
void configure_registry_provider(krabs::kernel::registry_provider& provider) //Imput the different event IDs for registry events.
{
    
     krabs::event_filter registry_filter(
     [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
         {
            krabs::schema schema(record, ctx.schema_locator);
            const auto id = schema.event_id();
            return id == 4624 || id == 4625 || id == 4649 || id == 4719 || id == 4765;
        });
        provider.add_filter(registry_filter);

    registry_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx)
    {
        try
        {
            krabs::schema schema(record, ctx.schema_locator);
            if (schema.event_id() == 4624 || schema.event_id() == 4625)
            {
                std::wcout << L"Event 4624 or 4625 received!" << std::endl;
            }
        }
        catch (const std::exception& e) 
        {
            std::cerr << "Error processing event: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown error processing event." << std::endl;
        }
    });
}
void configure_file_provider(krabs::kernel::file_io_provider& provider) //change to display the event name along with description of the event.
{

        krabs::event_filter file_filter(
        [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
        {
            krabs::schema schema(record, ctx.schema_locator);
            const auto id = schema.event_id();
            return id == 4624 || id == 4625;
        });
        provider.add_filter(file_filter);

    file_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx)
    {
        try
        {
            krabs::schema schema(record, ctx.schema_locator);
            if (schema.event_id() == 4624 || schema.event_id() == 4625)
            {
                std::wcout << L"Event 4624 or 4625 received!" << std::endl;
            }
        }
        catch (const std::exception& e) 
        {
            std::cerr << "Error processing event: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown error processing event." << std::endl;
        }
    });
}
void configure_network_provider(krabs::provider<>& provider) //change this to define what the event name is along with description of the event.
{
    provider.any(0xFFFFFFFFFFFFFFFF);

        krabs::event_filter network_filter(
        [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
        {
            krabs::schema schema(record, ctx.schema_locator);
            const auto id = schema.event_id();
            return id == 4624 || id == 4625;
        });
        provider.add_filter(network_filter);

    network_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx)
    {
        try
        {
            krabs::schema schema(record, ctx.schema_locator);
            if (schema.event_id() == 4624 || schema.event_id() == 4625)
            {
                std::wcout << L"Event 4624 or 4625 received!" << std::endl;
            }
        }
        catch (const std::exception& e) 
        {
            std::cerr << "Error processing event: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown error processing event." << std::endl;
        }
    });
}
void configure_process_provider(krabs::kernel::process_provider& provider) //Figure out what this even does.
{
        krabs::event_filter process_filter(
        [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
        {
            krabs::schema schema(record, ctx.schema_locator);
            const auto id = schema.event_id();
            return id == 4624 || id == 4625;
        });
        provider.add_filter(process_filter);

    process_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx)
    {
        try
        {
            krabs::schema schema(record, ctx.schema_locator);
            if (schema.event_id() == 4624 || schema.event_id() == 4625)
            {
                std::wcout << L"Event 4624 or 4625 received!" << std::endl;
            }
        }
        catch (const std::exception& e) 
        {
            std::cerr << "Error processing event: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown error processing event." << std::endl;
        }
    });
} 