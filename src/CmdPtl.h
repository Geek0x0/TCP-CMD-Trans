//  Created by caydyn on 14/7/15.


#ifndef _CMDPTL_h
#define _CMDPTL_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>	/*TCP Keep-Alive*/

//determine version
#define __CAYDYN_TCPCMD_LIB_VERSION 3	/*current lib version*/

//TCPCMD_LIB_VERSION (user specified user lib version, must set !) 

#if (TCPCMD_LIB_VERSION != __CAYDYN_TCPCMD_LIB_VERSION)
	#pragma message("err: use TCP CMD lib version error, please check")
#endif

#define ____DEBUG_FLAG
#define DEBUG_EXPORT	0

#define ____COMMON_DATA
#define true 	1
#define false	0

#define DEFAULT_PORT 		8989	/*默认通讯端口*/
#define MAX_CMD_NUM			100		/*最大命令主ID数量*/
#define GROUP 				100		/*最多支持的Socket数量*/
#define RECV_BUFF_LEN		1024	/*接收缓存大小*/
#define SEND_BUFF_LEN		4096	/*发送缓存大小*/
#define RECV_BUFF_POOL		4096	/*接收缓存池大小*/
#define RSP_OK				1121	/*回复正常信息*/
#define RSP_NO 				0524	/*回复错误信息*/
#define SOCKET_ERROR		-1		/*Socket错误*/
#define SOCKET_CLOSE		0		/*Socket关闭*/

#define ____FUNC_ERR_ID
#define SOCKET_IP_E			-1	/*获取IP地址错误*/
#define SOCKET_CREATE_E		-2	/*创建Socket错误*/
#define SOCKET_BIND_E		-3	/*Socket BIND 失败*/
#define SOCKET_LISTEN_E		-4	/*Socket 监听失败*/
#define SOCKET_CONN_E		-5	/*Socket 链接失败*/
#define SOCKET_SEND_E		-6	/*Socket 发送失败*/
#define SOCKET_RECV_E		-7	/*Socket Recv 错误*/

#define SN_OUT_RANGE		-8 	/*SN 超过范围，与上次SN*/
#define FUNC_NOT_REG		-9	/*回调函数未注册*/
#define MALLOC_ERR 			-10	/*开辟内存错误*/

#define ___TCP_KEEP_LIVE
#define KEEP_LIVE_TYPE			1	/*是否开启长连接*/
#define KEEP_LIVE_WAIT		15	/*长连接探测等待时间*/
#define KEEP_LIVE_INTERVAL	5	/*长连接探测间隔*/
#define KEEP_LIVE_COUNT		10	/*尝试探测次数*/
int ConnSocket;

#define __RSP_ERR_INFO

#define ____CMD_HEAD_STRUCT
#define CMD_HEAD_LEN	17	/*命令头长度*/
typedef struct {
	uint8_t 		flag[3];	/*命令头标志位*/
	uint64_t		cmd_sn;	/*命令序列号*/
	uint8_t		cmd_id;	/*命令主id号*/
	uint8_t		sub_cmd_id;	/*命令辅id号*/
	uint32_t		cmd_len;	/*命令长度*/
}__attribute__((__packed__)) CMD_HEAD;

#define ____RSP_HEAD_STRUCT
#define RSP_HEAD_LEN	17	/*回复头长度*/
typedef struct {
	uint8_t 		flag[3];	/*回复头标志位*/
	uint64_t		rsp_sn;	/*回复序列号*/
	uint8_t		rsp_id;	/*回复主id号*/
	uint8_t		sub_rsp_id;	/*回复辅id号*/
	uint32_t		rsp_len;	/*回复长度*/
}__attribute__((__packed__)) RSP_HEAD;

#define ____CALLBACK_FUNCTION
/*命令回调函数指针*/
typedef int (*CMDCallBackFunc)								\
	(int *ConnFD, CMD_HEAD * CMDHead, char *CMDBody);

/*命令回调函数指针数组，对应不同的Socket*/
CMDCallBackFunc CMDCallBack[GROUP][MAX_CMD_NUM];
/*注册回调函数*/
#define REGISTER_COMMAND(GROUP, ID, FUNC)				\
	CMDCallBack[GROUP][ID] = FUNC;

#define ___STATIC_DATA
uint64_t FLastSN;	/*Last CMD SN*/
uint64_t RLastSN;	/*Report last SN*/
uint64_t HLastSN;	/*Host last SN*/

#define ____NET_AND_LOCAL
#define NET_TO_LOCAL_U64(v)	(be64toh(v))
#define NET_TO_LOCAL_U32(v)	(be32toh(v))
#define NET_TO_LOCAL_U16(v)	(be16toh(v))
#define NET_TO_LOCAL_U8(v)	(v)

#define LOCAL_TO_NET_U64(v)	(htobe64(v))
#define LOCAL_TO_NET_U32(v)	(htobe32(v))
#define LOCAL_TO_NET_U16(v)	(htobe16(v))
#define LOCAL_TO_NET_U8(v)	(v)


/*
*
* @brief 获取控制口ip地址
*
* @param [out] ip 存放ip地址字符串
*
* @return 解析正确返回1，失败返回0
*
*/
static inline 
int get_command_port_ip(uint8_t *ip)
{
	char *cmd_get_ip1 = 
		"ifconfig | grep \"inet addr:\" | grep Bcast:";
	char *cmd_get_ip2 = 
		"ifconfig | grep inet | grep broadcast";
	FILE *pd = NULL;
	int nc = 0;

	pd = popen(cmd_get_ip1, "r");
	if(pd == NULL)
		return 0;
	nc = fscanf(pd, " inet addr:%hhu.%hhu.%hhu.%hhu ", 
		ip, ip+1, ip+2, ip+3);
	pclose(pd);
	if(nc == 4)
		return 1;

	pd = popen(cmd_get_ip2, "r");
	if(pd == NULL)
		return 0;
	nc = fscanf(pd, " inet %hhu.%hhu.%hhu.%hhu ", 
		ip, ip+1, ip+2, ip+3);
	pclose(pd);
	if(nc == 4)
		return 1;

	return 0;
}


/*
*
* @brief 创建服务端
*
* @param [in] PORT 监听的端口号
*
* @param [in] _SocketFD 已经创建的socket描述符
*
* @return 正确返回创建的socket描述符
*
*/
static inline int 
BuildServer(uint16_t PORT, int _SocketFD)
{
	int SocketFD, err;
	struct sockaddr_in ServerAddr;
	uint8_t PortIP[4] = { 0 };
	char *IP = calloc(sizeof(char), 8);

	err = get_command_port_ip(PortIP);
	if(err = 0)
		return SOCKET_IP_E;
	
	if(!_SocketFD) {
		//create socket
		SocketFD = socket(PF_INET, SOCK_STREAM, 0);
		if(SocketFD == -1)
			return SOCKET_CREATE_E;
	} else
		SocketFD = _SocketFD;
	
	memset(&ServerAddr, 0, sizeof(ServerAddr));
	ServerAddr.sin_family = PF_INET;
	
	if(PORT)
		ServerAddr.sin_port = htons(PORT);
	else
		ServerAddr.sin_port = htons(DEFAULT_PORT);
	
	sprintf (IP, "%u.%u.%u.%u",
		PortIP[0], PortIP[1], PortIP[2], PortIP[3]);
	printf("Server IP Addr:%s\n",IP);
	ServerAddr.sin_addr.s_addr = inet_addr(IP);
	
	//bind socket
	err = 
		bind(SocketFD, (struct sockaddr *) &ServerAddr,
			sizeof(struct sockaddr));
	if (err == -1)
		return SOCKET_BIND_E;

	//listen socket
	err = listen(SocketFD, 10);
	if (err == -1)
		return SOCKET_LISTEN_E;
	
	return SocketFD;
}

/*
*
* @brief 创建客户端
*
* @param [in] PORT 连接的端口号
*
* @param [in] PortIP 连接的ip地址
*
* @param [in] _SocketFD 已经创建的socket描述符
*
* @return 正确返回创建的socket描述符
*
*/
static inline int
BuildHost(uint16_t PORT, uint32_t PortIP, int _SocketFD)
{
	int SocketFD, err;
    struct sockaddr_in HostAddr;

   if(!_SocketFD) {
		SocketFD = socket(PF_INET, SOCK_STREAM, 0);
		if(SocketFD == -1)
			return SOCKET_CREATE_E;
	} else
		SocketFD = _SocketFD;

    HostAddr.sin_family = PF_INET;
    if(PORT)
		HostAddr.sin_port = htons(PORT);
	else
		HostAddr.sin_port = htons(DEFAULT_PORT);
	if(PortIP)
		HostAddr.sin_addr.s_addr = PortIP;
	else
		return SOCKET_IP_E;
	
    err = 
    	connect(SocketFD, (struct sockaddr *) &HostAddr,
    		sizeof(HostAddr));
    if (err == -1) 
        return SOCKET_CONN_E;
    return SocketFD;
}


/*
*
* @brief 注册回调函数
*
*/
static inline void
RegisterCmdCallback(uint8_t Group, uint32_t CallbackID,
	CMDCallBackFunc Func)
{
	REGISTER_COMMAND(Group, CallbackID, Func);
}

/*
*
* @brief 创建发送回复
*
* @param [in] ConnFD 连接socket描述符
*
* @param [in] Type 回复类型
*
* @param [in] CMDHead 接受到的命令头
*
* @param [in] Body 返回的内容
*
* @param [in] BodyLen 返回内容的长度
*
* @return 正确返回发送的内容长度
*
*/
static inline int
SetCMDResponse(int *ConnFD, uint16_t Type, 
	CMD_HEAD *CMDHead, char *Body, uint32_t BodyLen)
{
	int err;
	char *Buff = calloc(sizeof(char), SEND_BUFF_LEN);
	RSP_HEAD *RSPHead = calloc(1, sizeof(RSP_HEAD));

	if(!Buff)
		return MALLOC_ERR;
	
	memcpy(RSPHead->flag, "RSP", 3);
	RSPHead->rsp_sn = CMDHead->cmd_sn;

	if(Type == RSP_OK) {
		/*CMDHead 内容为网络字节序，无需转换*/
		RSPHead->rsp_id = CMDHead->cmd_id;
		RSPHead->sub_rsp_id = CMDHead->sub_cmd_id;
		RSPHead->rsp_len = LOCAL_TO_NET_U32(BodyLen);
		memcpy(Buff, (char *)RSPHead, RSP_HEAD_LEN);
		/*防止NULL产生错误*/
		if(Body)
			memcpy(Buff + RSP_HEAD_LEN, Body, BodyLen);
	}
	else if(Type == RSP_NO) {
		RSPHead->rsp_id = LOCAL_TO_NET_U8(0xFF);
		RSPHead->sub_rsp_id = LOCAL_TO_NET_U8((uint8_t)atoi(Body));
		RSPHead->rsp_len = LOCAL_TO_NET_U32(0);
		memcpy(Buff, (char *)RSPHead, RSP_HEAD_LEN);
		BodyLen = 0;
	}
	err = send(*ConnFD, (char *)Buff,
		RSP_HEAD_LEN + BodyLen, 0);
	if(err < 0) {
		*ConnFD = 0;
		return SOCKET_SEND_E;
	}
	else {
		free(Buff);
		return err;
	}
}

/*
*
* @brief 上报未知报文
*
* @param [in] HostFD 上位机socket描述符
*
* @param [in] Pkt 未知报文指针
*
* @param [out] Ret 接受到的回复报文
*
*/
static inline int
SendReport(int HostFD, struct rte_mbuf* Pkt, void *Ret)
{
	int err, len, curr = 0;
	CMD_HEAD *CMDHead = NULL;
	RSP_HEAD *RSPHead = NULL;
	void *Buff = calloc(1, 
		Pkt->pkt.data_len + CMD_HEAD_LEN);

	CMDHead = calloc(1, CMD_HEAD_LEN);
	CMDHead->cmd_sn = LOCAL_TO_NET_U64(RLastSN++);
	CMDHead->cmd_id = LOCAL_TO_NET_U8(255);
	CMDHead->sub_cmd_id = LOCAL_TO_NET_U8(0);
	CMDHead->cmd_len = 
		LOCAL_TO_NET_U32(Pkt->pkt.data_len);

	memcpy(Buff, CMDHead, CMD_HEAD_LEN);
	free(CMDHead);

	memcpy(Buff + CMD_HEAD_LEN, Pkt->pkt.data, Pkt->pkt.data_len);
    err = send(HostFD, Buff, Pkt->pkt.data_len + CMD_HEAD_LEN, 0);
    if(err >= Pkt->pkt.data_len) {
		free(Buff);
		free_pkt(Pkt);
	} else {
		free(Buff);
		return SOCKET_SEND_E;
	}
	
	RSPHead = calloc(1, RSP_HEAD_LEN);
	/*获取Header*/
	err = recv(HostFD, RSPHead, RSP_HEAD_LEN, 0);
	if(err <= 0)
		return err;

	/*获取body*/
	len = RSPHead->rsp_len;
	while(len - curr) {
		curr = recv(HostFD, Ret, 1024, 0);
		if(curr <= 0)
			return curr;
	}
	free(RSPHead);
}

/*
*
* @brief 处理接受到的命令
*
* @param [in] Group socket的index
*
* @param [in] ConnFD 连接的socket描述符
*
* @param [out] Ret 接受到的回复报文
*
* @return 返回回调函数的返回值
*/
static inline int 
FProcessRecvCmd(int Group, int *ConnFD)
{
	int len, err = true;
	CMD_HEAD *CMDHead = 
		calloc(sizeof(uint8_t), sizeof(CMD_HEAD));
	uint8_t *Body = NULL;

	if(!CMDHead)
		return MALLOC_ERR;
	/*仅获取Head长度用于判断和获取Body长度*/
	len = recv(*ConnFD, (uint8_t *)CMDHead, CMD_HEAD_LEN, 0);
	if(len <= 0) {
		*ConnFD = 0;
		return SOCKET_RECV_E;
	}
	if(!strstr((char *)CMDHead, "CMD"))
		return SOCKET_RECV_E;
#if DEBUG_EXPORT
	printf("\nRecv CMD SN %lu ID %lu SUB_ID %lu LEN %lu\n",
		NET_TO_LOCAL_U64(CMDHead->cmd_sn), 
		NET_TO_LOCAL_U8(CMDHead->cmd_id),
		NET_TO_LOCAL_U8(CMDHead->sub_cmd_id), 
		NET_TO_LOCAL_U32(CMDHead->cmd_len));
#endif
	/*判断SN是否重复*/
	if(NET_TO_LOCAL_U64(CMDHead->cmd_sn) == 1 && FLastSN > 1) {
		/*如果控制程序重启*/
		goto __GUI_RE;
	}
	if(NET_TO_LOCAL_U64(CMDHead->cmd_sn) - FLastSN != 1) {
		/*返回SN错误提示*/
		SetCMDResponse(ConnFD, RSP_NO, CMDHead, "255", 0);
		free(CMDHead);
		return SN_OUT_RANGE;
	}
__GUI_RE:
	FLastSN = NET_TO_LOCAL_U64(CMDHead->cmd_sn);
	Body = calloc(sizeof(uint8_t), 
		NET_TO_LOCAL_U32(CMDHead->cmd_len));
	if(!Body)
		return MALLOC_ERR;
	/*获取Body内容*/
	if(CMDHead->cmd_len) {
		len = recv(*ConnFD, Body, 
			NET_TO_LOCAL_U32(CMDHead->cmd_len), 0);
		if(len <= 0 || 
			len != NET_TO_LOCAL_U32(CMDHead->cmd_len)) {
			*ConnFD = 0;
			return SOCKET_RECV_E;
		}
	}
	/*调用注册回调函数*/
	if(CMDCallBack[Group][NET_TO_LOCAL_U8(CMDHead->cmd_id)] != NULL)
		err = CMDCallBack[Group][NET_TO_LOCAL_U8(CMDHead->cmd_id)](
			ConnFD, CMDHead, Body);
	else
		err =  FUNC_NOT_REG;
	/*清理*/
	free(CMDHead);
	free(Body);
	return err;
}

/*
*
* @brief 上位机处理回复(未完成)
*
*/
static inline int 
HProcessRecvCmd(char *Buff)
{
	int err;
	char *Serach = NULL;
	RSP_HEAD *RSPHead = malloc(sizeof(RSP_HEAD));
	char *Body = malloc(RECV_BUFF_LEN);

	Serach = strstr(Buff, "RSP");
	
	if(Serach) {
		while(Serach) {
			Serach = strstr(Serach + CMD_HEAD_LEN, "RSP");
			//TODO
		}
	} else {

	}
	
	free(Body);
	return true;
}

/*
*
* @brief 上位机处理发送命令为标准结构
*
* @param [out] CMDBody 命令主体数组
*
* @param [in] CMDmd 处理的命令个数
*
* @param [out] ID 命令主id数组
*
* @param [out] SUBID 命令辅id数组
*/
static inline int
HProcessSendCmd(char **CMDBody, uint16_t *CMDLen,
	uint8_t CMDmd, uint8_t *ID, uint8_t *SUBID)
{
	int c;
	char *Buff = NULL;
	CMD_HEAD *CMDHead = NULL;

	for(c = 0; c < CMDmd; c++) {
		Buff = calloc(sizeof(char), CMDLen[c] + CMD_HEAD_LEN);
		CMDHead = calloc(1, sizeof(CMD_HEAD));
		memcpy(CMDHead->flag, "CMD", 3);
		CMDHead->cmd_sn = NET_TO_LOCAL_U64(HLastSN);
		CMDHead->cmd_id = NET_TO_LOCAL_U8(ID[c]);
		CMDHead->sub_cmd_id = NET_TO_LOCAL_U8(SUBID[c]);
		CMDHead->cmd_len = NET_TO_LOCAL_U32(CMDLen[c]);
		memcpy(Buff, CMDHead, CMD_HEAD_LEN);
		if(CMDBody[c] != NULL)
			memcpy(Buff + CMD_HEAD_LEN, CMDBody[c], CMDLen[c]);

		free(CMDBody[c]);
		CMDBody[c] = Buff;
	}
	HLastSN++;
}

/*
*
* @brief 循环处理所有创建的socket
*
* @param [in] Type socket的类型
*
* @param [in] Socket 处理的socket数组
*
* @param [out] SocketNB 处理的socket数量
*
* @param [out] Ret 每个socket处理结果返回值
*/
static inline int 
LoopProcessSocket(uint8_t Type, int *Socket, uint8_t SocketNB, int *Ret)
{
	int ConnFD, s, err;
	socklen_t SocketLen;
	struct sockaddr_in Addr;

	for(s = 0; s < SocketNB; s++) {
		switch(Type) {
			case 'S': {
				SocketLen = sizeof(Addr);
				
				if(KEEP_LIVE_TYPE) {
				/*开启keep alive*/
					int keepalive = KEEP_LIVE_TYPE;
					int keepidle = KEEP_LIVE_WAIT; 
					int keepinterval = KEEP_LIVE_INTERVAL;
					int keepcount = KEEP_LIVE_COUNT; 

					if(!ConnSocket) {
						ConnFD = accept(Socket[s],
							(struct sockaddr *) &Addr, &SocketLen);
						if (ConnFD < 0) {
								Ret[s] = SOCKET_ERROR;
								continue;
						}
						/*设定tcp keep alive模式*/
						setsockopt(ConnFD, SOL_SOCKET, SO_KEEPALIVE, 
							(void *)&keepalive , sizeof(keepalive )); 
						setsockopt(ConnFD, SOL_TCP, TCP_KEEPIDLE, 
							(void*)&keepidle , sizeof(keepidle )); 
						setsockopt(ConnFD, SOL_TCP, TCP_KEEPINTVL, 
							(void *)&keepinterval , sizeof(keepinterval )); 
						setsockopt(ConnFD, SOL_TCP, TCP_KEEPCNT, 
							(void *)&keepcount , sizeof(keepcount )); 
						/*记录keep alive连接描述符*/
						ConnSocket = ConnFD;
					}
					Ret[s] = FProcessRecvCmd(s, &ConnSocket);
				} else {
				/*未开启keep alive模式*/
					ConnFD = accept(Socket[s],
						(struct sockaddr *) &Addr, &SocketLen);
					if (ConnFD < 0) {
							Ret[s] = SOCKET_ERROR;
							continue;
					}
					Ret[s] = FProcessRecvCmd(s, &ConnFD);
				}
			}
			break;
			case 'C':
				//HOST TODO
			break;
		}
	}
}

#endif
