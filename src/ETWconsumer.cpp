#include <thread>
#include <iostream>
#include <cassert>
#include "../ETW_consumer/krabs/krabs.hpp"
#include "../Include/names.h"

    static void configure_security_provider(krabs::provider<>& provider);
    static void configure_registry_provider(krabs::provider<>& provider);
    static void configure_file_provider(krabs::provider<>& provider);
    static void configure_network_provider(krabs::provider<>& provider);
    static void configure_process_provider(krabs::provider<>& provider);


 void ETWconsumer::start()
{
      krabs::user_trace trace(L"ETWconsumer");
      

      krabs::provider<> Security_provider(krabs::guid(L"{54849625-5478-4994-A5BA-3E3B0328C30D}"));
      krabs::provider<> Registry_provider(krabs::guid(L"{70eb4f03-c1de-4f73-a051-33d13d5413bd}"));
      krabs::provider<> File_provider(krabs::guid(L"{edd08927-9cc4-4e65-b970-c2560fb5c289}"));
      krabs::provider<> Network_provider(krabs::guid(L"{7dd42a49-5329-4832-8dfd-43d979153a88}"));
      krabs::provider<> Process_provider(krabs::guid(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"));

    // std::thread blasphamy;

      configure_security_provider(Security_provider);
      configure_registry_provider(Registry_provider);
      configure_file_provider(File_provider);
      configure_network_provider(Network_provider);
      configure_process_provider(Process_provider);

     trace.enable(Security_provider);
     trace.enable(Registry_provider);
     trace.enable(File_provider);
     trace.enable(Network_provider);
     trace.enable(Process_provider);

     
        try
            {
                trace.start();
            }
            catch (const std::exception& e)
            {
            std::cerr << "Fatal error in trace." << e.what() << std::endl;
         }
    trace.stop();

   /* if (blasphamy.joinable())
    {
        blasphamy.join();
    }*/
}

void configure_security_provider(krabs::provider<>& provider) //Imput all the event IDs you want to monitor for the security provider
{
    provider.any(0xFFFFFFFFFFFFFFFF);

    krabs::event_filter security_filter(
        [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
        {
            krabs::schema schema(record, ctx.schema_locator);
            const auto id = schema.event_id();
            return id == 4624 || id == 4625;
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
void configure_registry_provider(krabs::provider<>& provider) //Imput the different event IDs for registry events.
{
    provider.any(0xFFFFFFFFFFFFFFFF);
     krabs::event_filter registry_filter(
     [](const EVENT_RECORD& record, const krabs::trace_context& ctx) -> bool
         {
            krabs::schema schema(record, ctx.schema_locator);
            const auto id = schema.event_id();
            return id == 4624 || id == 4625;
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
void configure_file_provider(krabs::provider<>& provider) //change to display the event name along with description of the event.
{
    provider.any(0xFFFFFFFFFFFFFFFF);

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
void configure_process_provider(krabs::provider<>& provider) //Figure out what this even does.
{
    provider.any(0xFFFFFFFFFFFFFFFF);

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