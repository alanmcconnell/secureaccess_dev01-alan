#!/bin/bash

   aPort="3013";     aFrom="npm-start.sh default"  # if not in $1 or .env
   aStg="server3"    aSrvr="server.mjs"
   aApp="s31_iodd-data-api"
#  aMode="dev"      # or start for prod, or build

#       aRepo="IODD_/prod-master_v30428-et217p,wiForms"
#       aRepo="C:/WEBs/8020/VMs/et217p_formR0/webs/${aRepo}"
#       aPath="${aRepo}/${aStg}/${aApp}"
        aPath="$(realpath "$0")"; aPath="${aPath/\/npm-start.sh/}"; # echo "  ${aPath}"
  cd "${aPath}"

if [ "${aStg:0:6}" == "server" ]; then aEnv="${aPath}/api/.env"; else aEnv="${aPath}/_env"; fi
if [ "${aStg:0:6}" == "server" ]; then aStg1="[Ss]erver_"; aStg2="[Cc]lient_"; aStg3="Server";
                                  else aStg1="[Cc]lient_"; aStg2="[Ss]erver_"; aStg3="Client"; fi

if [ -e "${aEnv}" ]; then aRegX="^ *(${aStg1})*(PORT|Port|port) *= *"
        aPgm='/^#|('${aStg2}')/{next}; /'${aRegX}'[0-9]{4,5}/ { sub( /'${aRegX}'/, "" )'
        nPort=$( cat "${aEnv}" | awk "${aPgm}; print; exit }" );
if [ "${nPort}" != "" ]; then aPort=${nPort}; aFrom="${aEnv: -4} ${aStg3}_Port"; fi; fi
if [ "$1"       != "" ]; then aPort="$1"    ; aFrom="npm-start.sh arg"; fi

          NODEMON="../node_modules/.bin/nodemon"; bOK=$( ls -1 "${NODEMON}" )
if [ ! "${NODEMON}" ]; then NODEMON=node; fi

 echo -e "\n# ${NODEMON/*\//} ${aSrvr} ${aPort}  # (${aFrom})"; # exit
 echo    "------------------------------------------------------------------------------------"
#echo    "  ${aPath}"
#echo    ""
#exit
        bOK=$(        which chrome )
if [ "${bOK}" != "" ]; then chrome  "http://localhost:${aPort}"; fi

     "${NODEMON}" ${aSrvr}  ${aPort}
