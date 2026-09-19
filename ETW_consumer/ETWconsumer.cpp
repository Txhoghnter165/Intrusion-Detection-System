#include <iostream>
#include <cassert>
#include "../microsoft.o365.security.krabsetw.4.4.9/lib/native/include/krabs.hpp"

void start()
{
    krabs::user_trace trace(L"ETWconsumer");
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Process");
    provider.any(1);
    krabs::event_filter filter(krabs::predicates::id_is(1));
    filter.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
     krabs::schema schema(record, trace_context.schema_locator);
     assert(schema.event_id() == 1);
     std::wcout << L"Event 1 received!" << std::endl;
    });

    provider.add_filter(filter);
    trace.enable(provider);
    trace.start();
}