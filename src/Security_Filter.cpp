#include <iostream>
#include "../ETW_consumer/krabs/krabs.hpp"
#include "../include/arraying.h"
#include "../include/names.h"

void Security_Filter::start(krabs::schema& schema){
        switch (schema.event_id())
{
    case 4618:
        std::wcout << L"Event 4618: security event pattern occurred" << std::endl;
        break;

    case 4649:
        std::wcout << L"Event 4649: a possible replay attack was detected" << std::endl;
        break;

    case 4719:
        std::wcout << L"Event 4719: audit policy has been altered" << std::endl;
        break;

    case 4765:
        std::wcout << L"Event 4765: SID History was added to an account" << std::endl;
        break;

    case 4766:
        std::wcout << L"Event 4766: attempt to add SID history to an account failed" << std::endl;
        break;

    case 4794:
        std::wcout << L"Event 4794: attempt was made to set the directory services restore mode" << std::endl;
        break;

    case 4897:
        std::wcout << L"Event 4897: Role separation was enabled" << std::endl;
        break;

    case 4964:
        std::wcout << L"Event 4964: special groups have been assigned to a new logon" << std::endl;
        break;

    case 5124:
        std::wcout << L"Event 5124: A security setting was updated on the OCSP Responder Service" << std::endl;
        break;

    case 4621:
        std::wcout << L"Event 4621: recovered system from crash on audit failure. activity might not have been recorded" << std::endl;
        break;

    case 4675:
        std::wcout << L"Event 4675: SIDs were filtered" << std::endl;
        break;

    case 4692:
        std::wcout << L"Event 4692: Backup of data protection master key was attempted" << std::endl;
        break;

    case 4693:
        std::wcout << L"Event 4693: Recovery of data protection master key was attempted" << std::endl;
        break;

    case 1102:
        std::wcout << L"Event 1102: The audit log was cleared" << std::endl;
        break;

    case 4713:
        std::wcout << L"Event 4713: Kerberos policy was changed" << std::endl;
        break;

    case 4714:
        std::wcout << L"Event 4714: Encrypted data recovery policy was changed" << std::endl;
        break;

    case 4715:
        std::wcout << L"Event 4715: The audit policy (SACL) on an object was changed" << std::endl;
        break;

    case 4724:
        std::wcout << L"Event 4724: An attempt was made to reset an account's password" << std::endl;
        break;

    case 4727:
        std::wcout << L"Event 4727: A security-enabled global group was created" << std::endl;
        break;

    case 4735:
        std::wcout << L"Event 4735: A security-enabled local group was changed" << std::endl;
        break;

    case 4737:
        std::wcout << L"Event 4737: A security-enabled global group was changed" << std::endl;
        break;

    case 4739:
        std::wcout << L"Event 4739: Domain Policy was changed" << std::endl;
        break;

    case 4754:
        std::wcout << L"Event 4754: A security-enabled universal group was created" << std::endl;
        break;

    case 4755:
        std::wcout << L"Event 4755: A security-enabled universal group was changed" << std::endl;
        break;

    case 4764:
        std::wcout << L"Event 4764: A security-disabled group was deleted / A group's type was changed" << std::endl;
        break;

    case 4780:
        std::wcout << L"Event 4780: The ACL was set on accounts which are members of administrators groups" << std::endl;
        break;

    case 4865:
        std::wcout << L"Event 4865: A trusted forest information entry was added" << std::endl;
        break;

    case 4866:
        std::wcout << L"Event 4866: A trusted forest information entry was removed" << std::endl;
        break;

    case 4867:
        std::wcout << L"Event 4867: A trusted forest information entry was modified" << std::endl;
        break;

    case 4868:
        std::wcout << L"Event 4868: The certificate manager denied a pending certificate request" << std::endl;
        break;

    case 4870:
        std::wcout << L"Event 4870: Certificate Services revoked a certificate" << std::endl;
        break;

    case 4882:
        std::wcout << L"Event 4882: The security permissions for Certificate Services changed" << std::endl;
        break;

    case 4885:
        std::wcout << L"Event 4885: The audit filter for Certificate Services changed" << std::endl;
        break;

    case 4890:
        std::wcout << L"Event 4890: The certificate manager settings for Certificate Services changed" << std::endl;
        break;

    case 4892:
        std::wcout << L"Event 4892: A property of Certificate Services changed" << std::endl;
        break;

    case 4896:
        std::wcout << L"Event 4896: One or more rows have been deleted from the certificate database" << std::endl;
        break;

    case 4906:
        std::wcout << L"Event 4906: The CrashOnAuditFail value has changed" << std::endl;
        break;

    case 4907:
        std::wcout << L"Event 4907: Auditing settings on object were changed" << std::endl;
        break;

    case 4908:
        std::wcout << L"Event 4908: Special Groups Logon table modified" << std::endl;
        break;

    case 4912:
        std::wcout << L"Event 4912: Per User Audit Policy was changed" << std::endl;
        break;

    case 4960:
        std::wcout << L"Event 4960: IPsec dropped an inbound packet that failed an integrity check" << std::endl;
        break;

    case 4961:
        std::wcout << L"Event 4961: IPsec dropped an inbound packet that failed a replay check. could indicate a replay attack" << std::endl;
        break;

    case 4962:
        std::wcout << L"Event 4962: IPsec dropped an inbound packet that failed a replay check. too low sequence number to ensure it was not a replay" << std::endl;
        break;

    case 4963:
        std::wcout << L"Event 4963: IPsec dropped an inbound clear text packet that should have been secured" << std::endl;
        break;

    case 4965:
        std::wcout << L"Event 4965: IPsec received a packet from a remote computer with an incorrect Security Parameter Index" << std::endl;
        break;

    case 4976:
        std::wcout << L"Event 4976: During Main Mode negotiation, IPsec received an invalid negotiation packet" << std::endl;
        break;

    case 4977:
        std::wcout << L"Event 4977: During Quick Mode negotiation, IPsec received an invalid negotiation packet." << std::endl;
        break;

    case 4978:
        std::wcout << L"Event 4978: During Extended Mode negotiation, IPsec received an invalid negotiation packet" << std::endl;
        break;

    case 4983:
        std::wcout << L"Event 4983: An IPsec Extended Mode negotiation failed, corresponding Main Mode security association has been deleted." << std::endl;
        break;

    case 4984:
        std::wcout << L"Event 4984: An IPsec Extended Mode negotiation failed, corresponding Main Mode security association has been deleted" << std::endl;
        break;

    case 5027:
        std::wcout << L"Event 5027: The Windows Firewall Service was unable to retrieve the security policy from the local storage" << std::endl;
        break;

    case 5028:
        std::wcout << L"Event 5028: The Windows Firewall Service was unable to parse the new security policy" << std::endl;
        break;

    case 5029:
        std::wcout << L"Event 5029: The Windows Firewall Service failed to initialize the driver" << std::endl;
        break;

    case 5030:
        std::wcout << L"Event 5030: The Windows Firewall Service failed to start" << std::endl;
        break;

    case 5035:
        std::wcout << L"Event 5035: The Windows Firewall Driver failed to start" << std::endl;
        break;

    case 5037:
        std::wcout << L"Event 5037: The Windows Firewall Driver detected critical runtime error. Terminating" << std::endl;
        break;
    case 4610:
        std::wcout << L"Event 4610: An authentication package has been loaded by the Local Security Authority." << std::endl;
        break;

    case 4611:
        std::wcout << L"Event 4611: A trusted logon process has been registered with the Local Security Authority." << std::endl;
        break;

    case 4612:
        std::wcout << L"Event 4612: Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits." << std::endl;
        break;

    case 4614:
        std::wcout << L"Event 4614: A notification package has been loaded by the Security Account Manager." << std::endl;
        break;

    case 4615:
        std::wcout << L"Event 4615: Invalid use of LPC port." << std::endl;
        break;

    case 4616:
        std::wcout << L"Event 4616: The system time was changed." << std::endl;
        break;

    case 4622:
        std::wcout << L"Event 4622: A security package has been loaded by the Local Security Authority." << std::endl;
        break;

    case 4624:
        std::wcout << L"Event 4624: An account was successfully logged on." << std::endl;
        break;

    case 4625:
        std::wcout << L"Event 4625: An account failed to log on." << std::endl;
        break;

    case 4634:
        std::wcout << L"Event 4634: An account was logged off." << std::endl;
        break;

    case 4646:
        std::wcout << L"Event 4646: IKE DoS-prevention mode started." << std::endl;
        break;

    case 4647:
        std::wcout << L"Event 4647: User initiated logoff." << std::endl;
        break;

    case 4648:
        std::wcout << L"Event 4648: A logon was attempted using explicit credentials." << std::endl;
        break;

    case 4650:
        std::wcout << L"Event 4650: An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used." << std::endl;
        break;

    case 4651:
        std::wcout << L"Event 4651: An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication." << std::endl;
        break;

    case 4652:
        std::wcout << L"Event 4652: An IPsec Main Mode negotiation failed." << std::endl;
        break;

    case 4653:
        std::wcout << L"Event 4653: An IPsec Main Mode negotiation failed." << std::endl;
        break;

    case 4654:
        std::wcout << L"Event 4654: An IPsec Quick Mode negotiation failed." << std::endl;
        break;

    case 4655:
        std::wcout << L"Event 4655: An IPsec Main Mode security association ended." << std::endl;
        break;

    case 4656:
        std::wcout << L"Event 4656: A handle to an object was requested." << std::endl;
        break;

    case 4657:
        std::wcout << L"Event 4657: A registry value was modified." << std::endl;
        break;

    case 4658:
        std::wcout << L"Event 4658: The handle to an object was closed." << std::endl;
        break;

    case 4659:
        std::wcout << L"Event 4659: A handle to an object was requested with intent to delete." << std::endl;
        break;

    case 4660:
        std::wcout << L"Event 4660: An object was deleted." << std::endl;
        break;

    case 4661:
        std::wcout << L"Event 4661: A handle to an object was requested." << std::endl;
        break;

    case 4662:
        std::wcout << L"Event 4662: An operation was performed on an object." << std::endl;
        break;

    case 4663:
        std::wcout << L"Event 4663: An attempt was made to access an object." << std::endl;
        break;

    case 4664:
        std::wcout << L"Event 4664: An attempt was made to create a hard link." << std::endl;
        break;

    case 4665:
        std::wcout << L"Event 4665: An attempt was made to create an application client context." << std::endl;
        break;

    case 4666:
        std::wcout << L"Event 4666: An application attempted an operation." << std::endl;
        break;

    case 4667:
        std::wcout << L"Event 4667: An application client context was deleted." << std::endl;
        break;

    case 4668:
        std::wcout << L"Event 4668: An application was initialized." << std::endl;
        break;

    case 4670:
        std::wcout << L"Event 4670: Permissions on an object were changed." << std::endl;
        break;

    case 4671:
        std::wcout << L"Event 4671: An application attempted to access a blocked ordinal through the TBS." << std::endl;
        break;

    case 4672:
        std::wcout << L"Event 4672: Special privileges assigned to new logon." << std::endl;
        break;

    case 4673:
        std::wcout << L"Event 4673: A privileged service was called." << std::endl;
        break;

    case 4674:
        std::wcout << L"Event 4674: An operation was attempted on a privileged object." << std::endl;
        break;

    case 4688:
        std::wcout << L"Event 4688: A new process has been created." << std::endl;
        break;

    case 4689:
        std::wcout << L"Event 4689: A process has exited." << std::endl;
        break;

    case 4690:
        std::wcout << L"Event 4690: An attempt was made to duplicate a handle to an object." << std::endl;
        break;

    case 4691:
        std::wcout << L"Event 4691: Indirect access to an object was requested." << std::endl;
        break;

    case 4694:
        std::wcout << L"Event 4694: Protection of auditable protected data was attempted." << std::endl;
        break;

    case 4695:
        std::wcout << L"Event 4695: Unprotection of auditable protected data was attempted." << std::endl;
        break;

    case 4696:
        std::wcout << L"Event 4696: A primary token was assigned to process." << std::endl;
        break;

    case 4697:
        std::wcout << L"Event 4697: Attempt to install a service." << std::endl;
        break;

    case 4698:
        std::wcout << L"Event 4698: A scheduled task was created." << std::endl;
        break;

    case 4699:
        std::wcout << L"Event 4699: A scheduled task was deleted." << std::endl;
        break;

    case 4700:
        std::wcout << L"Event 4700: A scheduled task was enabled." << std::endl;
        break;

    case 4701:
        std::wcout << L"Event 4701: A scheduled task was disabled." << std::endl;
        break;

    case 4702:
        std::wcout << L"Event 4702: A scheduled task was updated." << std::endl;
        break;

    case 4704:
        std::wcout << L"Event 4704: A user right was assigned." << std::endl;
        break;

    case 4705:
        std::wcout << L"Event 4705: A user right was removed." << std::endl;
        break;

    case 4707:
        std::wcout << L"Event 4707: A trust to a domain was removed." << std::endl;
        break;

    case 4709:
        std::wcout << L"Event 4709: IPsec Services was started." << std::endl;
        break;

    case 4710:
        std::wcout << L"Event 4710: IPsec Services was disabled." << std::endl;
        break;

    case 4711:
        std::wcout << L"Event 4711: May contain any one of the following: PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer. PAStore Engine applied Active Directory storage IPsec policy on the computer. PAStore Engine applied local registry storage IPsec policy on the computer. PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer. PAStore Engine failed to apply Active Directory storage IPsec policy on the computer. PAStore Engine failed to apply local registry storage IPsec policy on the computer. PAStore Engine failed to apply some rules of the active IPsec policy on the computer. PAStore Engine failed to load directory storage IPsec policy on the computer. PAStore Engine loaded directory storage IPsec policy on the computer. PAStore Engine failed to load local storage IPsec policy on the computer. PAStore Engine loaded local storage IPsec policy on the computer.PAStore Engine polled for changes to the active IPsec policy and detected no changes." << std::endl;
        break;

    case 4712:
        std::wcout << L"Event 4712: IPsec Services encountered a potentially serious failure." << std::endl;
        break;

    case 4717:
        std::wcout << L"Event 4717: System security access was granted to an account." << std::endl;
        break;

    case 4718:
        std::wcout << L"Event 4718: System security access was removed from an account." << std::endl;
        break;

    case 4720:
        std::wcout << L"Event 4720: A user account was created." << std::endl;
        break;

    case 4722:
        std::wcout << L"Event 4722: A user account was enabled." << std::endl;
        break;

    case 4723:
        std::wcout << L"Event 4723: An attempt was made to change an account's password." << std::endl;
        break;

    case 4725:
        std::wcout << L"Event 4725: A user account was disabled." << std::endl;
        break;

    case 4726:
        std::wcout << L"Event 4726: A user account was deleted." << std::endl;
        break;

    case 4728:
        std::wcout << L"Event 4728: A member was added to a security-enabled global group." << std::endl;
        break;

    case 4729:
        std::wcout << L"Event 4729: A member was removed from a security-enabled global group." << std::endl;
        break;

    case 4730:
        std::wcout << L"Event 4730: A security-enabled global group was deleted." << std::endl;
        break;

    case 4731:
        std::wcout << L"Event 4731: A security-enabled local group was created." << std::endl;
        break;

    case 4732:
        std::wcout << L"Event 4732: A member was added to a security-enabled local group." << std::endl;
        break;

    case 4733:
        std::wcout << L"Event 4733: A member was removed from a security-enabled local group." << std::endl;
        break;

    case 4734:
        std::wcout << L"Event 4734: A security-enabled local group was deleted." << std::endl;
        break;

    case 4738:
        std::wcout << L"Event 4738: A user account was changed." << std::endl;
        break;

    case 4740:
        std::wcout << L"Event 4740: A user account was locked out." << std::endl;
        break;

    case 4741:
        std::wcout << L"Event 4741: A computer account was changed." << std::endl;
        break;

    case 4742:
        std::wcout << L"Event 4742: A computer account was changed." << std::endl;
        break;

    case 4743:
        std::wcout << L"Event 4743: A computer account was deleted." << std::endl;
        break;

    case 4744:
        std::wcout << L"Event 4744: A security-disabled local group was created." << std::endl;
        break;

    case 4745:
        std::wcout << L"Event 4745: A security-disabled local group was changed." << std::endl;
        break;

    case 4746:
        std::wcout << L"Event 4746: A member was added to a security-disabled local group." << std::endl;
        break;

    case 4747:
        std::wcout << L"Event 4747: A member was removed from a security-disabled local group." << std::endl;
        break;

    case 4748:
        std::wcout << L"Event 4748: A security-disabled local group was deleted." << std::endl;
        break;

    case 4749:
        std::wcout << L"Event 4749: A security-disabled global group was created." << std::endl;
        break;

    case 4750:
        std::wcout << L"Event 4750: A security-disabled global group was changed." << std::endl;
        break;

    case 4751:
        std::wcout << L"Event 4751: A member was added to a security-disabled global group." << std::endl;
        break;

    case 4752:
        std::wcout << L"Event 4752: A member was removed from a security-disabled global group." << std::endl;
        break;

    case 4753:
        std::wcout << L"Event 4753: A security-disabled global group was deleted." << std::endl;
        break;

    case 4756:
        std::wcout << L"Event 4756: A member was added to a security-enabled universal group." << std::endl;
        break;

    case 4757:
        std::wcout << L"Event 4757: A member was removed from a security-enabled universal group." << std::endl;
        break;

    case 4758:
        std::wcout << L"Event 4758: A security-enabled universal group was deleted." << std::endl;
        break;

    case 4759:
        std::wcout << L"Event 4759: A security-disabled universal group was created." << std::endl;
        break;

    case 4760:
        std::wcout << L"Event 4760: A security-disabled universal group was changed." << std::endl;
        break;

    case 4761:
        std::wcout << L"Event 4761: A member was added to a security-disabled universal group." << std::endl;
        break;

    case 4762:
        std::wcout << L"Event 4762: A member was removed from a security-disabled universal group." << std::endl;
        break;

    case 4767:
        std::wcout << L"Event 4767: A user account was unlocked." << std::endl;
        break;

    case 4768:
        std::wcout << L"Event 4768: A Kerberos authentication ticket (TGT) was requested." << std::endl;
        break;

    case 4769:
        std::wcout << L"Event 4769: A Kerberos service ticket was requested." << std::endl;
        break;

    case 4770:
        std::wcout << L"Event 4770: A Kerberos service ticket was renewed." << std::endl;
        break;

    case 4771:
        std::wcout << L"Event 4771: Kerberos pre-authentication failed." << std::endl;
        break;

    case 4772:
        std::wcout << L"Event 4772: A Kerberos authentication ticket request failed." << std::endl;
        break;

    case 4774:
        std::wcout << L"Event 4774: An account was mapped for logon." << std::endl;
        break;

    case 4775:
        std::wcout << L"Event 4775: An account could not be mapped for logon." << std::endl;
        break;

    case 4776:
        std::wcout << L"Event 4776: The domain controller attempted to validate the credentials for an account." << std::endl;
        break;

    case 4777:
        std::wcout << L"Event 4777: The domain controller failed to validate the credentials for an account." << std::endl;
        break;

    case 4778:
        std::wcout << L"Event 4778: A session was reconnected to a Window Station." << std::endl;
        break;

    case 4779:
        std::wcout << L"Event 4779: A session was disconnected from a Window Station." << std::endl;
        break;

    case 4781:
        std::wcout << L"Event 4781: The name of an account was changed." << std::endl;
        break;

    case 4782:
        std::wcout << L"Event 4782: The password hash an account was accessed." << std::endl;
        break;

    case 4783:
        std::wcout << L"Event 4783: A basic application group was created." << std::endl;
        break;

    case 4784:
        std::wcout << L"Event 4784: A basic application group was changed." << std::endl;
        break;

    case 4785:
        std::wcout << L"Event 4785: A member was added to a basic application group." << std::endl;
        break;

    case 4786:
        std::wcout << L"Event 4786: A member was removed from a basic application group." << std::endl;
        break;

    case 4787:
        std::wcout << L"Event 4787: A nonmember was added to a basic application group." << std::endl;
        break;

    case 4788:
        std::wcout << L"Event 4788: A nonmember was removed from a basic application group." << std::endl;
        break;

    case 4789:
        std::wcout << L"Event 4789: A basic application group was deleted." << std::endl;
        break;

    case 4790:
        std::wcout << L"Event 4790: An LDAP query group was created." << std::endl;
        break;

    case 4793:
        std::wcout << L"Event 4793: The Password Policy Checking API was called." << std::endl;
        break;

    case 4800:
        std::wcout << L"Event 4800: The workstation was locked." << std::endl;
        break;

    case 4801:
        std::wcout << L"Event 4801: The workstation was unlocked." << std::endl;
        break;

    case 4802:
        std::wcout << L"Event 4802: The screen saver was invoked." << std::endl;
        break;

    case 4803:
        std::wcout << L"Event 4803: The screen saver was dismissed." << std::endl;
        break;

    case 4864:
        std::wcout << L"Event 4864: A namespace collision was detected." << std::endl;
        break;

    case 4869:
        std::wcout << L"Event 4869: Certificate Services received a resubmitted certificate request." << std::endl;
        break;

    case 4871:
        std::wcout << L"Event 4871: Certificate Services received a request to publish the certificate revocation list (CRL)." << std::endl;
        break;

    case 4872:
        std::wcout << L"Event 4872: Certificate Services published the certificate revocation list (CRL)." << std::endl;
        break;

    case 4873:
        std::wcout << L"Event 4873: A certificate request extension changed." << std::endl;
        break;

    case 4874:
        std::wcout << L"Event 4874: One or more certificate request attributes changed." << std::endl;
        break;

    case 4875:
        std::wcout << L"Event 4875: Certificate Services received a request to shut down." << std::endl;
        break;

    case 4876:
        std::wcout << L"Event 4876: Certificate Services backup started." << std::endl;
        break;

    case 4877:
        std::wcout << L"Event 4877: Certificate Services backup completed." << std::endl;
        break;

    case 4878:
        std::wcout << L"Event 4878: Certificate Services restore started." << std::endl;
        break;

    case 4879:
        std::wcout << L"Event 4879: Certificate Services restore completed." << std::endl;
        break;

    case 4880:
        std::wcout << L"Event 4880: Certificate Services started." << std::endl;
        break;

    case 4881:
        std::wcout << L"Event 4881: Certificate Services stopped." << std::endl;
        break;

    case 4883:
        std::wcout << L"Event 4883: Certificate Services retrieved an archived key." << std::endl;
        break;

    case 4884:
        std::wcout << L"Event 4884: Certificate Services imported a certificate into its database." << std::endl;
        break;

    case 4886:
        std::wcout << L"Event 4886: Certificate Services received a certificate request." << std::endl;
        break;

    case 4887:
        std::wcout << L"Event 4887: Certificate Services approved a certificate request and issued a certificate." << std::endl;
        break;

    case 4888:
        std::wcout << L"Event 4888: Certificate Services denied a certificate request." << std::endl;
        break;

    case 4889:
        std::wcout << L"Event 4889: Certificate Services set the status of a certificate request to pending." << std::endl;
        break;

    case 4891:
        std::wcout << L"Event 4891: A configuration entry changed in Certificate Services." << std::endl;
        break;

    case 4893:
        std::wcout << L"Event 4893: Certificate Services archived a key." << std::endl;
        break;

    case 4894:
        std::wcout << L"Event 4894: Certificate Services imported and archived a key." << std::endl;
        break;

    case 4895:
        std::wcout << L"Event 4895: Certificate Services published the CA certificate to Active Directory Domain Services." << std::endl;
        break;

    case 4898:
        std::wcout << L"Event 4898: Certificate Services loaded a template." << std::endl;
        break;

    case 4902:
        std::wcout << L"Event 4902: The Per-user audit policy table was created." << std::endl;
        break;

    case 4904:
        std::wcout << L"Event 4904: An attempt was made to register a security event source." << std::endl;
        break;

    case 4905:
        std::wcout << L"Event 4905: An attempt was made to unregister a security event source." << std::endl;
        break;

    case 4909:
        std::wcout << L"Event 4909: The local policy settings for the TBS were changed." << std::endl;
        break;

    case 4910:
        std::wcout << L"Event 4910: The Group Policy settings for the TBS were changed." << std::endl;
        break;

    case 4928:
        std::wcout << L"Event 4928: An Active Directory replica source naming context was established." << std::endl;
        break;

    case 4929:
        std::wcout << L"Event 4929: An Active Directory replica source naming context was removed." << std::endl;
        break;

    case 4930:
        std::wcout << L"Event 4930: An Active Directory replica source naming context was modified." << std::endl;
        break;

    case 4931:
        std::wcout << L"Event 4931: An Active Directory replica destination naming context was modified." << std::endl;
        break;

    case 4932:
        std::wcout << L"Event 4932: Synchronization of a replica of an Active Directory naming context has begun." << std::endl;
        break;

    case 4933:
        std::wcout << L"Event 4933: Synchronization of a replica of an Active Directory naming context has ended." << std::endl;
        break;

    case 4934:
        std::wcout << L"Event 4934: Attributes of an Active Directory object were replicated." << std::endl;
        break;

    case 4935:
        std::wcout << L"Event 4935: Replication failure begins." << std::endl;
        break;

    case 4936:
        std::wcout << L"Event 4936: Replication failure ends." << std::endl;
        break;

    case 4937:
        std::wcout << L"Event 4937: A lingering object was removed from a replica." << std::endl;
        break;

    case 4944:
        std::wcout << L"Event 4944: The following policy was active when the Windows Firewall started." << std::endl;
        break;

    case 4945:
        std::wcout << L"Event 4945: A rule was listed when the Windows Firewall started." << std::endl;
        break;

    case 4946:
        std::wcout << L"Event 4946: A change has been made to Windows Firewall exception list. A rule was added." << std::endl;
        break;

    case 4947:
        std::wcout << L"Event 4947: A change has been made to Windows Firewall exception list. A rule was modified." << std::endl;
        break;

    case 4948:
        std::wcout << L"Event 4948: A change has been made to Windows Firewall exception list. A rule was deleted." << std::endl;
        break;

    case 4949:
        std::wcout << L"Event 4949: Windows Firewall settings were restored to the default values." << std::endl;
        break;

    case 4950:
        std::wcout << L"Event 4950: A Windows Firewall setting has changed." << std::endl;
        break;

    case 4951:
        std::wcout << L"Event 4951: A rule has been ignored because its major version number was not recognized by Windows Firewall." << std::endl;
        break;

    case 4952:
        std::wcout << L"Event 4952: Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall. The other parts of the rule will be enforced." << std::endl;
        break;

    case 4953:
        std::wcout << L"Event 4953: A rule has been ignored by Windows Firewall because it could not parse the rule." << std::endl;
        break;

    case 4954:
        std::wcout << L"Event 4954: Windows Firewall Group Policy settings have changed. The new settings have been applied." << std::endl;
        break;

    case 4956:
        std::wcout << L"Event 4956: Windows Firewall has changed the active profile." << std::endl;
        break;

    case 4957:
        std::wcout << L"Event 4957: Windows Firewall did not apply the following rule." << std::endl;
        break;

    case 4958:
        std::wcout << L"Event 4958: Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer." << std::endl;
        break;

    case 4979:
        std::wcout << L"Event 4979: IPsec Main Mode and Extended Mode security associations were established." << std::endl;
        break;

    case 4980:
        std::wcout << L"Event 4980: IPsec Main Mode and Extended Mode security associations were established." << std::endl;
        break;

    case 4981:
        std::wcout << L"Event 4981: IPsec Main Mode and Extended Mode security associations were established." << std::endl;
        break;

    case 4982:
        std::wcout << L"Event 4982: IPsec Main Mode and Extended Mode security associations were established." << std::endl;
        break;

    case 4985:
        std::wcout << L"Event 4985: The state of a transaction has changed." << std::endl;
        break;

    case 5024:
        std::wcout << L"Event 5024: The Windows Firewall Service has started successfully." << std::endl;
        break;

    case 5025:
        std::wcout << L"Event 5025: The Windows Firewall Service has been stopped." << std::endl;
        break;

    case 5031:
        std::wcout << L"Event 5031: The Windows Firewall Service blocked an application from accepting incoming connections on the network." << std::endl;
        break;

    case 5032:
        std::wcout << L"Event 5032: Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network." << std::endl;
        break;

    case 5033:
        std::wcout << L"Event 5033: The Windows Firewall Driver has started successfully." << std::endl;
        break;

    case 5034:
        std::wcout << L"Event 5034: The Windows Firewall Driver has been stopped." << std::endl;
        break;

    case 5039:
        std::wcout << L"Event 5039: A registry key was virtualized." << std::endl;
        break;

    case 5040:
        std::wcout << L"Event 5040: A change has been made to IPsec settings. An Authentication Set was added." << std::endl;
        break;

    case 5041:
        std::wcout << L"Event 5041: A change has been made to IPsec settings. An Authentication Set was modified." << std::endl;
        break;

    case 5042:
        std::wcout << L"Event 5042: A change has been made to IPsec settings. An Authentication Set was deleted." << std::endl;
        break;

    case 5043:
        std::wcout << L"Event 5043: A change has been made to IPsec settings. A Connection Security Rule was added." << std::endl;
        break;

    case 5044:
        std::wcout << L"Event 5044: A change has been made to IPsec settings. A Connection Security Rule was modified." << std::endl;
        break;

    case 5045:
        std::wcout << L"Event 5045: A change has been made to IPsec settings. A Connection Security Rule was deleted." << std::endl;
        break;

    case 5046:
        std::wcout << L"Event 5046: A change has been made to IPsec settings. A Crypto Set was added." << std::endl;
        break;

    case 5047:
        std::wcout << L"Event 5047: A change has been made to IPsec settings. A Crypto Set was modified." << std::endl;
        break;

    case 5048:
        std::wcout << L"Event 5048: A change has been made to IPsec settings. A Crypto Set was deleted." << std::endl;
        break;

    case 5049:
        std::wcout << L"Event 5049: An IPsec Security Association was deleted." << std::endl;
        break;

    case 5050:
        std::wcout << L"Event 5050: An attempt to programmatically disable the Windows Firewall using a call to InetFwProfile.FirewallEnabled(False)." << std::endl;
        break;

    case 5051:
        std::wcout << L"Event 5051: A file was virtualized." << std::endl;
        break;

    case 5056:
        std::wcout << L"Event 5056: A cryptographic self test was performed." << std::endl;
        break;

    case 5057:
        std::wcout << L"Event 5057: A cryptographic primitive operation failed." << std::endl;
        break;

    case 5058:
        std::wcout << L"Event 5058: Key file operation." << std::endl;
        break;

    case 5059:
        std::wcout << L"Event 5059: Key migration operation." << std::endl;
        break;

    case 5060:
        std::wcout << L"Event 5060: Verification operation failed." << std::endl;
        break;

    case 5061:
        std::wcout << L"Event 5061: Cryptographic operation." << std::endl;
        break;

    case 5062:
        std::wcout << L"Event 5062: A kernel-mode cryptographic self test was performed." << std::endl;
        break;

    case 5063:
        std::wcout << L"Event 5063: A cryptographic provider operation was attempted." << std::endl;
        break;

    case 5064:
        std::wcout << L"Event 5064: A cryptographic context operation was attempted." << std::endl;
        break;

    case 5065:
        std::wcout << L"Event 5065: A cryptographic context modification was attempted." << std::endl;
        break;

    case 5066:
        std::wcout << L"Event 5066: A cryptographic function operation was attempted." << std::endl;
        break;

    case 5067:
        std::wcout << L"Event 5067: A cryptographic function modification was attempted." << std::endl;
        break;

    case 5068:
        std::wcout << L"Event 5068: A cryptographic function provider operation was attempted." << std::endl;
        break;

    case 5069:
        std::wcout << L"Event 5069: A cryptographic function property operation was attempted." << std::endl;
        break;

    case 5070:
        std::wcout << L"Event 5070: A cryptographic function property modification was attempted." << std::endl;
        break;

    case 5120:
        std::wcout << L"Event 5120: OCSP Responder Service Started." << std::endl;
        break;

    case 5121:
        std::wcout << L"Event 5121: OCSP Responder Service Stopped." << std::endl;
        break;

    case 5122:
        std::wcout << L"Event 5122: A configuration entry changed in OCSP Responder Service." << std::endl;
        break;

    case 5123:
        std::wcout << L"Event 5123: A configuration entry changed in OCSP Responder Service." << std::endl;
        break;

    case 5125:
        std::wcout << L"Event 5125: A request was submitted to the OCSP Responder Service." << std::endl;
        break;

    case 5126:
        std::wcout << L"Event 5126: Signing Certificate was automatically updated by the OCSP Responder Service." << std::endl;
        break;

    case 5127:
        std::wcout << L"Event 5127: The OCSP Revocation Provider successfully updated the revocation information." << std::endl;
        break;

    case 5136:
        std::wcout << L"Event 5136: A directory service object was modified." << std::endl;
        break;

    case 5137:
        std::wcout << L"Event 5137: A directory service object was created." << std::endl;
        break;

    case 5138:
        std::wcout << L"Event 5138: A directory service object was undeleted." << std::endl;
        break;

    case 5139:
        std::wcout << L"Event 5139: A directory service object was moved." << std::endl;
        break;

    case 5140:
        std::wcout << L"Event 5140: A network share object was accessed." << std::endl;
        break;

    case 5141:
        std::wcout << L"Event 5141: A directory service object was deleted." << std::endl;
        break;

    case 5152:
        std::wcout << L"Event 5152: The Windows Filtering Platform blocked a packet." << std::endl;
        break;

    case 5153:
        std::wcout << L"Event 5153: A more restrictive Windows Filtering Platform filter has blocked a packet." << std::endl;
        break;

    case 5154:
        std::wcout << L"Event 5154: The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections." << std::endl;
        break;

    case 5155:
        std::wcout << L"Event 5155: The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections." << std::endl;
        break;

    case 5156:
        std::wcout << L"Event 5156: The Windows Filtering Platform has allowed a connection." << std::endl;
        break;

    case 5157:
        std::wcout << L"Event 5157: The Windows Filtering Platform has blocked a connection." << std::endl;
        break;

    case 5158:
        std::wcout << L"Event 5158: The Windows Filtering Platform has permitted a bind to a local port." << std::endl;
        break;

    case 5159:
        std::wcout << L"Event 5159: The Windows Filtering Platform has blocked a bind to a local port." << std::endl;
        break;

    case 5376:
        std::wcout << L"Event 5376: Credential Manager credentials were backed up." << std::endl;
        break;

    case 5377:
        std::wcout << L"Event 5377: Credential Manager credentials were restored from a backup." << std::endl;
        break;

    case 5378:
        std::wcout << L"Event 5378: The requested credentials delegation was disallowed by policy." << std::endl;
        break;

    case 5440:
        std::wcout << L"Event 5440: The following callout was present when the Windows Filtering Platform Base Filtering Engine started." << std::endl;
        break;

    case 5441:
        std::wcout << L"Event 5441: The following filter was present when the Windows Filtering Platform Base Filtering Engine started." << std::endl;
        break;

    case 5442:
        std::wcout << L"Event 5442: The following provider was present when the Windows Filtering Platform Base Filtering Engine started." << std::endl;
        break;

    case 5443:
        std::wcout << L"Event 5443: The following provider context was present when the Windows Filtering Platform Base Filtering Engine started." << std::endl;
        break;

    case 5444:
        std::wcout << L"Event 5444: The following sublayer was present when the Windows Filtering Platform Base Filtering Engine started." << std::endl;
        break;

    case 5446:
        std::wcout << L"Event 5446: A Windows Filtering Platform callout has been changed." << std::endl;
        break;

    case 5447:
        std::wcout << L"Event 5447: A Windows Filtering Platform filter has been changed." << std::endl;
        break;

    case 5448:
        std::wcout << L"Event 5448: A Windows Filtering Platform provider has been changed." << std::endl;
        break;

    case 5449:
        std::wcout << L"Event 5449: A Windows Filtering Platform provider context has been changed." << std::endl;
        break;

    case 5450:
        std::wcout << L"Event 5450: A Windows Filtering Platform sublayer has been changed." << std::endl;
        break;

    case 5451:
        std::wcout << L"Event 5451: An IPsec Quick Mode security association was established." << std::endl;
        break;

    case 5452:
        std::wcout << L"Event 5452: An IPsec Quick Mode security association ended." << std::endl;
        break;

    case 5453:
        std::wcout << L"Event 5453: An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started." << std::endl;
        break;

    case 5456:
        std::wcout << L"Event 5456: PAStore Engine applied Active Directory storage IPsec policy on the computer." << std::endl;
        break;

    case 5457:
        std::wcout << L"Event 5457: PAStore Engine failed to apply Active Directory storage IPsec policy on the computer." << std::endl;
        break;

    case 5458:
        std::wcout << L"Event 5458: PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer." << std::endl;
        break;

    case 5459:
        std::wcout << L"Event 5459: PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer." << std::endl;
        break;

    case 5460:
        std::wcout << L"Event 5460: PAStore Engine applied local registry storage IPsec policy on the computer." << std::endl;
        break;

    case 5461:
        std::wcout << L"Event 5461: PAStore Engine failed to apply local registry storage IPsec policy on the computer." << std::endl;
        break;

    case 5462:
        std::wcout << L"Event 5462: PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP Security Monitor snap-in to diagnose the problem." << std::endl;
        break;

    case 5463:
        std::wcout << L"Event 5463: PAStore Engine polled for changes to the active IPsec policy and detected no changes." << std::endl;
        break;

    case 5464:
        std::wcout << L"Event 5464: PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services." << std::endl;
        break;

    case 5465:
        std::wcout << L"Event 5465: PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully." << std::endl;
        break;

    case 5466:
        std::wcout << L"Event 5466: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. Any changes made to the Active Directory IPsec policy since the last poll could not be applied." << std::endl;
        break;

    case 5467:
        std::wcout << L"Event 5467: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy. The cached copy of the Active Directory IPsec policy is no longer being used." << std::endl;
        break;

    case 5468:
        std::wcout << L"Event 5468: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the Active Directory IPsec policy is no longer being used." << std::endl;
        break;

    case 5471:
        std::wcout << L"Event 5471: PAStore Engine loaded local storage IPsec policy on the computer." << std::endl;
        break;

    case 5472:
        std::wcout << L"Event 5472: PAStore Engine failed to load local storage IPsec policy on the computer." << std::endl;
        break;

    case 5473:
        std::wcout << L"Event 5473: PAStore Engine loaded directory storage IPsec policy on the computer." << std::endl;
        break;

    case 5474:
        std::wcout << L"Event 5474: PAStore Engine failed to load directory storage IPsec policy on the computer." << std::endl;
        break;

    case 5477:
        std::wcout << L"Event 5477: PAStore Engine failed to add quick mode filter." << std::endl;
        break;

    case 5478:
        std::wcout << L"Event 5478: IPsec Services has started successfully." << std::endl;
        break;

    case 5479:
        std::wcout << L"Event 5479: IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks." << std::endl;
        break;

    case 5480:
        std::wcout << L"Event 5480: IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem." << std::endl;
        break;

    case 5483:
        std::wcout << L"Event 5483: IPsec Services failed to initialize RPC server. IPsec Services could not be started." << std::endl;
        break;

    case 5484:
        std::wcout << L"Event 5484: IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks." << std::endl;
        break;

    case 5485:
        std::wcout << L"Event 5485: IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem." << std::endl;
        break;

    case 5632:
        std::wcout << L"Event 5632: A request was made to authenticate to a wireless network." << std::endl;
        break;

    case 5633:
        std::wcout << L"Event 5633: A request was made to authenticate to a wired network." << std::endl;
        break;

    case 5712:
        std::wcout << L"Event 5712: A Remote Procedure Call (RPC) was attempted." << std::endl;
        break;

    case 5827:
        std::wcout << L"Event 5827: The Netlogon service denied a vulnerable Netlogon secure channel connection from a machine account." << std::endl;
        break;

    case 5828:
        std::wcout << L"Event 5828: The Netlogon service denied a vulnerable Netlogon secure channel connection using a trust account." << std::endl;
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