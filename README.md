# Schneider Electric Unified MEssaging Application Services 

Repository for Schneider Electric (SE) Unified Messaging Application Services (UMAS) stuff

The repository started as part of the DFRWS 2023 challenge (The Troubled Elevator) takes a deep dive into the domain of Industrial Control Systems (ICS), specifically focusing on programmable logic controllers (PLC), which can be found at https://github.com/dfrws/dfrws2023-challenge.

The challenge appears to use the SE Modicon M221 PLC which employes UMAS. Other SE PLC which use UMAS include:
  * Modicon M221
  * Modicon M340
  * Modicon M580 

## SE UMAS Wireshark Dissector

The LUA script based dissector has been tested on Apple Mac OS X 11.7.10 using Wireshark 4.2.4.

### Installation - Apple Mac OS X

  * `mkdir -p ~/.config/wireshark/plugins`
  * `cp se_umas_dissector.lua ~/.config/wireshark/plugins/`

# References

  * https://github.com/dfrws/dfrws2023-challenge
  * https://wiki.wireshark.org/Lua/Dissectors

## SE UMAS References

  * https://tuxcare.com/blog/new-modicon-plc-vulnerabilities-uncovered-by-researchers/
  * https://vulners.com/talos/TALOS-2019-0764
  * https://securelist.com/the-secrets-of-schneider-electrics-umas-protocol/107435/
    * https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/?utm_source=securelist&utm_medium=link&utm_campaign=the-secrets-of-schneider-electrics-umas-protocol/
  * https://medium.com/tenable-techblog/examining-crypto-and-bypassing-authentication-in-schneider-electric-plcs-m340-m580-f37cf9f3ff34
  * https://hitcon.org/2021/agenda/b128a44d-c492-410f-b04c-045548ce0590/Debacle%20of%20The%20Maginot%20Line%EF%BC%9AGoing%20Deeper%20into%20Schneider%20Modicon%20PAC%20Security.pdf
