#include <iostream>
#include "../ETW_consumer/krabs/krabs.hpp"
#include "../include/arraying.h"

void Security_Filter(){
            break;

    case 5888:
        std::wcout << L"Event 5888: An object in the COM+ Catalog was modified." << std::endl;
        break;

    case 5889:
        std::wcout << L"Event 5889: An object was deleted from the COM+ Catalog." << std::endl;
        break;

    case 5890:
        std::wcout << L"Event 5890: An object was added to the COM+ Catalog." << std::endl;
        break;

    case 6008:
        std::wcout << L"Event 6008: The previous system shutdown was unexpected." << std::endl;
        break;

    case 6144:
        std::wcout << L"Event 6144: Security policy in the Group Policy objects has been applied successfully." << std::endl;
        break;

    case 6145:
        std::wcout << L"Event 6145: One or more errors occurred while processing security policy in the Group Policy objects." << std::endl;
        break;

    case 6272:
        std::wcout << L"Event 6272: Network Policy Server granted access to a user." << std::endl;
        break;

    case 6273:
        std::wcout << L"Event 6273: Network Policy Server denied access to a user." << std::endl;
        break;

    case 6274:
        std::wcout << L"Event 6274: Network Policy Server discarded the request for a user." << std::endl;
        break;

    case 6275:
        std::wcout << L"Event 6275: Network Policy Server discarded the accounting request for a user." << std::endl;
        break;

    case 6276:
        std::wcout << L"Event 6276: Network Policy Server quarantined a user." << std::endl;
        break;

    case 6277:
        std::wcout << L"Event 6277: Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy." << std::endl;
        break;

    case 6278:
        std::wcout << L"Event 6278: Network Policy Server granted full access to a user because the host met the defined health policy." << std::endl;
        break;

    case 6279:
        std::wcout << L"Event 6279: Network Policy Server locked the user account due to repeated failed authentication attempts." << std::endl;
        break;

    case 6280:
        std::wcout << L"Event 6280: Network Policy Server unlocked the user account." << std::endl;
        break;

    case 24577:
        std::wcout << L"Event 24577: Encryption of volume started." << std::endl;
        break;

    case 24578:
        std::wcout << L"Event 24578: Encryption of volume stopped." << std::endl;
        break;

    case 24579:
        std::wcout << L"Event 24579: Encryption of volume completed." << std::endl;
        break;

    case 24580:
        std::wcout << L"Event 24580: Decryption of volume started." << std::endl;
        break;

    case 24581:
        std::wcout << L"Event 24581: Decryption of volume stopped." << std::endl;
        break;

    case 24582:
        std::wcout << L"Event 24582: Decryption of volume completed." << std::endl;
        break;

    case 24583:
        std::wcout << L"Event 24583: Conversion worker thread for volume started." << std::endl;
        break;

    case 24584:
        std::wcout << L"Event 24584: Conversion worker thread for volume temporarily stopped." << std::endl;
        break;

    case 24586:
        std::wcout << L"Event 24586: An error was encountered converting volume." << std::endl;
        break;

    case 24588:
        std::wcout << L"Event 24588: The conversion operation on volume %2 encountered a bad sector error. Please validate the data on this volume." << std::endl;
        break;

    case 24592:
        std::wcout << L"Event 24592: An attempt to automatically restart conversion on volume %2 failed." << std::endl;
        break;

    case 24593:
        std::wcout << L"Event 24593: Metadata write: Volume %2 returning errors while trying to modify metadata. If failures continue, decrypt volume." << std::endl;
        break;

    case 24594:
        std::wcout << L"Event 24594: Metadata rebuild: An attempt to write a copy of metadata on volume %2 failed and may appear as disk corruption. If failures continue, decrypt volume." << std::endl;
        break;

    case 24595:
        std::wcout << L"Event 24595: Volume %2 contains bad clusters. These clusters will be skipped during conversion." << std::endl;
        break;

    case 24621:
        std::wcout << L"Event 24621: Initial state check: Rolling volume conversion transaction on %2." << std::endl;
        break;

    default:
        break;
}

}