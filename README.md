# SAP HANA Audit Policy Templates for SAP S/4HANA
[![REUSE status](https://api.reuse.software/badge/github.com/SAP-samples/s4hana-hana-audit-policies)](https://api.reuse.software/info/github.com/SAP-samples/s4hana-hana-audit-policies)

## Description
This project provides HANA audit policy templates for the SAP HANA database tenant used by SAP S/4HANA. The HANA audit policy templates for S/4HANA provide a set of policies.

1. **Mandatory HANA Audit Policies** (File: 1_hana_audit_policy_mandatory.sql)  
A first set of policies defined as mandatory ensure traceability of security relevant changes. These have the prefix '_SAP_'. They are identical to the audit policies provided by "SAP HANA Cockpit Audit Policy Wizard" (starting with SAP HANA Cockpit 2.0 SP13).
1. **S/4HANA Schema Access Log HANA Audit Policies** (File: 2_s4hana_hana_audit_policy_recommended.sql)  
The second set of policies define "recommended" policies for S/4 systems. These have the prefix '_SAPS4_'. These policies vary with the usage of the SAP HANA DB and cannot be defined identical for all systems.
1. **S/4HANA Optional HANA Audit Policies** (File: 3_s4hana_hana_audit_policy_optional.sql)  
The third set called “optional” suggests policy definition for extended system changelog and monitoring. These have the prefix '_SAPS4_Opt_'.

Please refer to [SAP Note 3016478](https://launchpad.support.sap.com/#/notes/3016478) for more details and explanations.

## Requirements
To use those policies you need [SAP S/4HANA](https://www.sap.com/products/central-finance.html)

## Download and Installation
Information how to list and adjust HANA audit policies can be found at [SAP HANA Platform](https://help.sap.com/viewer/p/SAP_HANA_PLATFORM).

## Known Issues
If technical users (e.g. ABAP Database user <SAPABAP1>, e.g. SAPHANADB) are not handled as described in the SQL files, a high number of HANA audit log events might be generated.

## How to obtain support
[Create an issue](https://github.com/SAP-samples/s4hana-hana-audit-policies/issues) in this repository if you find a bug or have questions about the content.
 
For additional support, [ask a question in SAP Community](https://answers.sap.com/questions/ask.html).

## Contributing
When contributing to this repository, please first discuss the changes you wish to make through an issue, email, or any other method with the owners of this repository.

## License
Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This project is licensed under the Apache Software License, version 2.0 except as noted otherwise in the [LICENSE](LICENSES/Apache-2.0.txt) file.
