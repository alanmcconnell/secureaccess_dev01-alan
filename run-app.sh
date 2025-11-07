#!/bin/bash

  nPrj=55  # Can't be greater than 64   # .(51013.05.1 SecureAccess Project Number
  nUseThisClientPort="55301"            # .(51013.05.1 RAM Override Client Port for SecureAccess)

  nStg=4; if [[ "$(realpath "$0")" == *dev* ]]; then nStg=3; fi
          if [[ "$(realpath "$0")" == *tes* ]]; then nStg=2; fi
          if [[ "$(realpath "$0")" == *pro* ]]; then nStg=1; fi
  nApp=1
  nPort="${nPrj}${nStg}##"

  if [ "$1" == "" ]; then
     echo -e "\n  Run Client and/or Server App(s) for Project 54"
     echo -e   "  Usage: run-app [c|s|a]{nStg}{nApp} [-b] [-q]"
     echo -e   ""
     echo -e   "    c|s|a = c)Client, s)Server, or a)both"
     echo -e   "    nStg  = Stage: 1)Prod1, 2)Test2, 3)Dev03, 4-9)Dev0[4-9]"
     echo -e   "    nApp  = [0-9][0-9]: client#/c##, server#/s##, or both/a##"
     echo -e   "     -b   = Debug, -q = Quietly"
     echo -e   ""
     echo -e   "  Example: run-app a32  # run both Client and Server App no. 32"
     echo -e   "     Runs: Client App on Port 54332 and Server API on Port 54382"
     if [ "${OS:0:3}" != "Win" ]; then echo ""; fi
     exit; fi

  aQuiet=""; if [ "$2" == "-q" ]; then aQuiet="--quiet "; set -- "$1" "${@:3}"; fi
             if [ "$3" == "-q" ]; then aQuiet="--quiet "; fi

# ---------------------------------------------------

# Function to kill process on a specific port
function chkPort() {
    local port=$1

    echo -e "  Checking ${aCS} port $port..."

    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows (Git Bash)
        local pid=$(netstat -ano | findstr ":$port" | awk '{print $5}' | head -1)
        if [ "$pid" != "0" ] && [ ! -z "$pid" ]; then
            echo "  Killing windows process $pid for port $port"
#           taskkill /PID $pid /F > /dev/null 2>&1
            MSYS2_ARG_CONV_EXCL="/PID;/F" /c/Windows/System32/taskkill.exe /PID $pid /F 2>&1 | awk '{ print "  " $0 }'
        fi
    else
        # Linux/macOS
        local pid=$(lsof -ti:$port)
        if [ "$pid" != "0" ] && [ ! -z "$pid" ]; then
            echo "  Killing linux process $pid for port $port"
            kill -9 $pid > /dev/null 2>&1 | awk '{ print "  " $0 }'
        fi
    fi
}
# ---------------------------------------------------

function setPort() { # $1 = 3201, 3251 or 64361: Proj#: 3,64; Stage#: 1)Prod, 2)Test, 3)Dev3, 4-9)Dev4-9; Client#/Server#: 0-4/5-9; App#: 1-9
#   Runs 1st for getName with "c##"
    csn=${1:1:1}     # Client#/Server#
    ano=${1:2:1}     # App#
    prj="${2:0:2}"; if [ "${#2}" == "5" ]; then prj="${2:0:3}"; fi  # Proj# + Stage#   33 or 643
    nsp=5;       if [ "${1:0:1}" == "c" ]; then nsp=0; fi
    nPort="${prj}$(( nsp + csn ))${ano}";
    aApp="${1:0:1}${csn}${ano}"

#   echo -e "\n  setPort[1] ${1} prj: ${prj}, nsp: ${nsp}, csn: ${csn}, ano: ${ano} == nPort: ${nPort}, aApp: ${aApp}\n"; exit
    aServer="server${csn}"; if [ "${csn}" == "0" ]; then aServer="server"; fi
    aClient="client${csn}"; if [ "${csn}" == "0" ]; then aClient="client"; fi
#   echo "--nPort: ${nPort}"; exit
    }
# ---------------------------------------------------

function getAppName() {
   aAppName="Unknown"; setPort "$1" "$2"; aFldr="docs"; # echo "  nPort: ${nPort}"; exit
#   echo "-- \$1 \$2: '$1' '$2', aApp: '${aApp}'"  # aApp is set by setPort
if [ "${1:0:1}" == "c" ]; then aFldr="${aClient}"; aCS="C${aClient:1:5}"; fi
if [ "${1:0:1}" == "s" ]; then aFldr="${aServer}"; aCS="S${aServer:1:5}"; fi
if [ -d "${aFldr}" ]; then
   aAppName=$(  find "./${aFldr}" -maxdepth 1 -type d -name "${aApp}_*"                  | awk '{ sub( /.+\//, ""   ); print; exit }' )
   fi
#  echo "--- ./${aFldr}/${aApp}_* -- aAppName: ${aAppName}";
if [ "$3" == "q" ]; then return; fi                                                     # .(51007.01.1 RAM Don't check)
if [ "${aAppName}" == "" ] || [ "${aAppName}" == "Unknown" ]; then                      # .(51007.01.2 RAM Check Unknown too)
   echo -e "\n* ${aCS} App, ${aApp}_*, not found in folder, ${aFldr}.";
   if [ "${OS:0:3}" != "Win" ]; then echo ""; fi; exit 1;
   fi
   if [ -f "${aServer}/${aAppName}/.env" ]; then
   aHost="$( cat "${aServer}/${aAppName}/.env" | awk '/SERVER_HOST/ && !/^#/ { sub( /.+= */, ""); print; next; }' | tr -d "'" | tr -d '"' )" # .(50911.03.x)
   fi
   if [ "${aHost}" == "" ]; then aHost="localhost"; fi;                                 # .(50911.03.x)
   }
# ---------------------------------------------------

function setServerAPI_URL() {                                                           # .(50911.04.1 RAM Write function Beg)
         aServerDir="$1"
         aClientDir="$2"
#        nServerPort="$(    cat "${aServerDir}/_config.js" | awk '/^ *SERVER_PORT *=/           { sub( /.+= */, "" ); print }' | tr -d "'" | tr -d '"' )"   # .(51013.05.5 RAM Use _config.js, not .env)
#        aServerHost="$(    cat "${aServerDir}/_config.js" | awk '/^ *SERVER_HOST *=/           { sub( /.+= */, "" ); print }' | tr -d "'" | tr -d '"' )"   # .(51013.05.6)
#        aServerAPI_URL="$( cat "${aServerDir}/_config.js" | awk '/^[, "]*SERVER_API_URL[ "]*:/ { sub( /^[, "]*SERVER_API_URL[ "]*:/, "" ); sub( /.+= */, "" ); print }' | tr -d "'" | tr -d '"' )"   # .(51013.05.7)
         aServerAPI_URL="$( cat "${aServerDir}/_config.js" | awk '/^[, "]*SECURE_API_URL[ "]*:/ { sub( /^[, "]*SECURE_API_URL[ "]*:/, "" ); sub( /.+= */, "" ); print }' | tr -d "'" | tr -d '"' )"   # .(51013.05.7)
         nServerPort="$(   echo "${aServerAPI_URL}" | awk '{ sub( /.+:/, "" ); sub( /\/.+/, "" ); print }' )"                                               # .(51013.05.5 RAM Use _config.js, not .env)
         aServerHost="$(   echo "${aServerAPI_URL}" | awk '{ sub( /:.+/, "" ); print }' )"  # .(51013.05.6)
#        echo "  Setting SERVER_API_URL to: ${aServerAPI_URL// /} in ${aClientDir}/_config.js"

   if [ ! -f "${aClientDir}/_config.js" ]; then                                             # .(51013.05.8 RAM Use _config.js, not config.js Beg)
         echo 'var CONFIG = '                              > "${aClientDir}/_config.js"
         echo ' { "SERVER_API_URL": "{SERVER_API_URL}"'   >> "${aClientDir}/_config.js"
         echo ' , "CLIENT_URL":     "{CLIENT_URL}"'       >> "${aClientDir}/_config.js"
         echo '  }'                                       >> "${aClientDir}/_config.js"      # .(51013.05.8 End)
         fi
#        aAWKpgm='/SERVER_API_URL:/ { print "  SERVER_API_URL: \"'${aServerHost// /}:${nServerPort}${aServerAPI_URL}'\","; next }
         aAWKpgm='
/^[, "]*CLIENT_PATH[ "]*:/    { print ", \"CLIENT_PATH\":    \"http://'${aHost}:${nPort}'\""; next }
/^[, "]*SERVER_API_URL[ "]*:/ { print ", \"SERVER_API_URL\": \"'${aServerAPI_URL// /}'\""; next }
                  { print }'
         cat "${aClientDir}/_config.js" | awk "${aAWKpgm}" > "${aClientDir}/_config.tmp.js"
#        echo -e "  aAWKpgm: \n${aAWKpgm}"; echo " _config.tmp.js: "; cat "${aClientDir}/_config.tmp.js"
#        mv  "${aClientDir}/_config.tmp.js" "${aClientDir}/_config.js"
#        echo  "  Setting SERVER_API_URL to: ${aServerHost// /}:${nServerPort}${aServerAPI_URL} in ${aClientDir}/_config.js"
         echo  "   Setting CLIENT_PATH    to: http://${aHost}:${nPort} in ${aClientDir}/_config.js"
         echo  "       and SERVER_API_URL to: ${aServerAPI_URL// /} "
         }                                                                              # .(50911.04.1 End)
# ---------------------------------------------------
function runServer() {
#                        echo "\n  runServer( '$1', '$2' )"
    setPort "$1" "$2"  # Sets aServer, aApp and nPort
#   chkPort ${nPort}   # Kill any existing processes on our ports
    getAppName $1 $2;  # echo "  Server nPort: ${nPort} for ${aAppName}"; return
#   echo -e "\n  runServer[1] Client nPort: ${nPort} for ${aAppName}";                  # .(50113.05.3 RAM ??? To get the client folder)

#   Install dependencies if needed
    bDoit="0"; if [ "${3:0:2}" == "-d" ]; then bDoit="1"; fi
 if [ ! -d "${aServer}/node_modules"   ]; then bDoit="1"; fi
 if [ "${bDoit}" == "1" ] && [ -f "${aServer}/package.json" ]; then

    echo -e "\n  Installing ${aServer} dependencies..."
    cd ${aServer}
    npm install
    cd ..
    fi
 if [ "$(command -v nodemon)" == "" ]; then npm install -g nodemon >/dev/null 2>&1; fi

    echo -e "\n  Starting ${aServer}, ${aAppName}, on port ${nPort}..."

    cd ${aServer}/${aAppName}
    chkPort ${nPort}   # Kill any existing processes on our ports

    aExt='mjs'; if [ -f "server.js" ]; then aExt='js'; fi
echo "  node --trace-deprecation ${aQuiet}\"server.${aExt}\""; echo ""
        node --trace-deprecation ${aQuiet}"server.${aExt}" &

    SERVER_PID=$!
#   echo "  Server is running at: http://localhost:${nPort}/api"
#   echo "  Server is running at: http://${aHost}:${nPort}"
#   if [ "${aQuiet}" == "" ]; then echo ""; fi
    cd ../..
    }
# ---------------------------------------------------

function runClient() {
#                        echo "\n  runClient( '$1', '$2' )"
    getAppName "s${1:1}" $2 "q"; aServerName=${aAppName}
    getAppName "c${1:1}" $2;
#   echo -e "\n  runClient[1] Client nPort: ${nPort} for ${aAppName}";                  # .(50113.05.3 RAM ??? To get the client folder)

 if [ "${nUseThisClientPort}" == "" ]; then      # .(50113.05.2 Beg)
    setPort "$1" "$2"  # Sets aClient, aApp and nPort
    else
    nPort="${nUseThisClientPort}"
    fi                                           # .(50113.05.2 End)
#   chkPort ${nPort}   # Kill any existing processes on our ports
#   getAppName $1 $2;  # echo -e "  Client nPort: ${nPort} for ${aAppName}\n";          # .(50113.05.3 RAM ??? Why was this here a 2nd time)
#   echo "  runClient[2] \$2: '$2', nPort: '${nPort}', aServerName: '${aServerName}'"

#   setServerAPI_URL "${aServer}/${aServerName}" "${aClient}/${aAppName}"; # exit       # .(50911.04.2 RAM Use it)

#   Install dependencies if needed
    bDoit="0"; if [ "${3:0:2}" == "-d" ]; then bDoit="1"; fi
 if [ ! -d "${aClient}/node_modules"   ]; then bDoit="1"; fi
 if [ "${bDoit}" == "1" ] && [ -f "${aClient}/package.json" ]; then

    echo -e "\n  Installing ${aClient} dependencies..."
    cd ${aClient}
    npm install
    cd ..
    fi

 if [ "$(command -v live-server)" == "" ]; then npm install -g live-server >/dev/null 2>&1; fi

    echo -e "\n  Starting ${aClient}, ${aAppName}, on port ${nPort}..."

    chkPort ${nPort}   # Kill any existing processes on our ports
    setServerAPI_URL "${aServer}/${aServerName}" "${aClient}/${aAppName}"; # exit       # .(50911.04.2 RAM Use it)

# echo "  live-server ${aQuiet}--port=${nPort} --open=${aAppName}/ --watch=.,../${aServer}/${aServerName}"    # .(50926.05.2)
#         live-server ${aQuiet}--port=${nPort} --open=${aAppName}/ --watch=.,../${aServer}/${aServerName} &   # .(50926.05.2)
  echo "  live-server ${aQuiet}--port=${nPort} --open=${aClient}/${aAppName} --watch=${aClient}/${aAppName},${aServer}/${aServerName}"    # .(50926.05.2)
          live-server ${aQuiet}--port=${nPort} --open=${aClient}/${aAppName} --watch=${aClient}/${aAppName},${aServer}/${aServerName} &   # .(50926.05.2)

    CLIENT_PID=$!
#   echo "  Client is running in: $(pwd)/index.html"
#   echo "  Client is running in: $(pwd)/${aAppName}/index.html"
    echo "  Client is running in: $(pwd)/${aClient}/${aAppName}/index.html"
    echo "  Client is running at: http://${aHost}:${nPort}"
    cd ../..
    }
# ----------------------------------------------------------------------------------------------

 if [ "${1:0:1}" == "s" ] || [ "${1:0:1}" == "a" ]; then
    runServer "s${1:1:2}" ${nPort}                        # .(50911.04.3 RAM Removes 3rd arg)
    sleep 6  # Wait for server to start
    fi
 if [ "${1:0:1}" == "c" ] || [ "${1:0:1}" == "a" ]; then
    runClient "c${1:1:2}" ${nPort}                        # .(50911.04.4)
    fi
# ---------------------------------------------------

    echo -e "\n  Press Ctrl+C to stop one or both processes\n"
#   if [ "${OS:0:3}" != "Win" ]; then echo ""; fi;

#   Wait for user interrupt
    trap "kill $SERVER_PID $CLIENT_PID; exit" INT
    wait
