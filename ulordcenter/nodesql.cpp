#include <string>
#include <boost/log/trivial.hpp>  
#include <iostream>
#include <boost/lexical_cast.hpp>  
#include <boost/algorithm/string.hpp>

#include "codec.h"

#include "nodesql.h"
#include "mastenode.h"
#include "connection_pool.h"
#include "key.h"
#include "utilstrencodings.h"
#include "initwallet.h"
#include "messagesigner.h"
#include "primitives/transaction.h"

using namespace muduo;
using namespace muduo::net;

using namespace std;
using namespace boost;

std::string g_privkeystr;
std::string g_pubkeystr;

std::map<COutPoint , CMstNodeData> g_mstdatamap;
unsigned int  g_curtime;
const unsigned int   TIME_INTERVAL = 120;
bool FindFromMasterNodeMemory( COutPoint masterVin, std::vector<CMstNodeData> & vecnode  )
{
    std::map<COutPoint, CMstNodeData>::iterator it  =   g_mstdatamap.find(masterVin);
//   加个时间判断 超过一定的时间 就重新度数据库 
   if(it != g_mstdatamap.end())
   {
       CMstNodeData mstNodeData  = it->second;
	   if(mstNodeData._validflag <= 0)
	   {
	   	  g_mstdatamap.erase(it);
          return false;
	   }
       if(mstNodeData._time > g_curtime  - TIME_INTERVAL) 
       {
          vecnode.push_back(it->second);
          return true;
       }
       else // 超时 
       {
          g_mstdatamap.erase(it);
          return false;
       }
   }
   
   return false;
       
}

void AddMasterNodeMemory(COutPoint masterVin ,int  invalidflag  )
{
    CMstNodeData mstnode(0,masterVin.hash.GetHex(), masterVin.n);
    mstnode._validflag= invalidflag; // 0 is invalid;  1 is valid
    mstnode._time = g_curtime; 

    std::map<COutPoint, CMstNodeData>::iterator it  =   g_mstdatamap.find(masterVin);
   //   加个时间判断 超过一定的时间 就重新度数据库 
   if(it != g_mstdatamap.end())
   {
      it->second._validflag=invalidflag;
   }
   else
   {
      g_mstdatamap.insert(pair<COutPoint,CMstNodeData>(masterVin,mstnode ));
   }  
}

void   AddMasterNodeMemory(COutPoint masterVin, CMstNodeData & node)
{
   node._time = g_curtime;
   std::map<COutPoint, CMstNodeData>::iterator it  =   g_mstdatamap.find(masterVin);
   if(it != g_mstdatamap.end())
   {
      it->second._validflag=node._validflag; 
   }
   else   
   {
       g_mstdatamap.insert(pair<COutPoint,CMstNodeData>(masterVin, node)); 
   } 
}

// sign  COutPoint
std::string SignMessage( COutPoint vin, int64_t timeStamps)
{
   CKey keyRet;
   CPubKey pubkeyRet;
   GetKeyFromString(keyRet, pubkeyRet, g_privkeystr, g_pubkeystr);
    
   //CPubKey testKey(ParseHex(g_pubkeystr));

   /*cout<< "Pubkey: str=" << g_pubkeystr << endl
   		<< "center key=" << pubkeyRet.GetID().ToString() << endl
   		<< "ulord key=" << testKey.GetID().ToString() << endl;*/

    CMessageSigner messSign;
    //CMessageSigner messVery;

    std::vector<unsigned char> vchSigRet;
    std::vector<unsigned char> vchkey;

    messSign.SignMessage(vin.ToString(), timeStamps, vchSigRet, keyRet);
    //cout<<"vchsigret "<< HexStr(vchSigRet)<<endl<<"vchsig "<< EncodeBase64(&vchSigRet[0], vchSigRet.size())<<endl<<"pubkey "<<pubkeyRet.GetID().ToString()<<endl;
    return HexStr(vchSigRet);
}

// sign for register certificate
std::string  SignMessage( std::string txid, int32_t index, std::string addr, int64_t validdate)
{
   CKey keyRet;
   CPubKey pubkeyRet;
   GetKeyFromString(  keyRet,  pubkeyRet,  g_privkeystr,   g_pubkeystr ) ;
    
   CPubKey testKey(ParseHex(g_pubkeystr));

    CMessageSigner messSign;

    std::vector<unsigned char> vchSigRet;
    std::vector<unsigned char> vchkey;

    messSign.SignMessage(txid, index, addr, validdate, vchSigRet, keyRet);

    return HexStr(vchSigRet);
}

int   ParseQuest(const TcpConnectionPtr & tcpcli,const std::string &buf, LengthHeaderCodec& codec )
{
    // const TcpConnectionPtr  tcpcli;
    ConnPool* pPool =  ConnPool::GetInstance();
    g_curtime  = time(NULL);
    mstnodequest  mstquest;  
    std::istringstream is(buf);  
    boost::archive::binary_iarchive ia(is);  
    ia >> mstquest;//从一个保存序列化数据的string里面反序列化，从而得到原来的对象。
    uint256 txid;
    txid.SetHex(mstquest._txid);
    std::vector<CMstNodeData> vecnode;
    COutPoint mnVin = COutPoint(txid, mstquest._voutid);
    if(mstquest._questtype == MST_QUEST_ONE)
    {
       // 先从内存中找 如果找不到就从数据库找  超时连接要断掉 超过1分钟
       if(FindFromMasterNodeMemory(mnVin, vecnode)==true)
       {
           // find        
          cout << " FindFromMasterNodeMemory  true "   << endl;
       }
       else 
       {
           //sql::Connection *  pConn = pPool->GetConnection();
           sql::Connection *  pConn = pPool->CreateConnection();
           if(pConn==NULL)
           {    
               cout << "error  pConn  get is null "   << endl;
               return 0;
           }         
   
           ReadMasterNodeToNet(pConn, mstquest._txid, mstquest._voutid, vecnode); 
           if(vecnode.size()==0)
           {
              AddMasterNodeMemory(mnVin, 0);
              CMstNodeData node(0,mstquest._txid, mstquest._voutid);
              node._validflag=0;
              cout << "find from sql   get is null "   << endl;
              
              vecnode.push_back( node);
           }
           else
           {
               AddMasterNodeMemory(mnVin, vecnode[0]);
           } 
           
           cout << "find from sql   get  size  " << vecnode.size()  << endl;
            
           //pPool->ReleaseConnection(pConn);
           pPool->DestroyConnection(pConn);
       }
    }
    else if(mstquest._questtype ==MST_QUEST_ALL )
    {
       sql::Connection *  pConn = pPool->GetConnection();
       if(pConn==NULL)
       {
           cout << "error  pConn  get is null "   << endl;
           return 0;
       } 
       ReadAllNodeToNet(pConn, vecnode );
       pPool->ReleaseConnection(pConn);  

    }

    mstnoderes  mstres(mstquest._msgversion);
    mstres._num= vecnode.size();
    //mstres._signstr = SignMessage(vecnode[0]._masteraddr, mstquest._timeStamps);
    std::ostringstream os;  
    boost::archive::binary_oarchive oa(os);  
    oa<<mstres; 
    for(auto node : vecnode) 
    {
    	cout << "write in msg Masternode " << node._txid << " voutid = " << node._voutid << " valid flag = " << node._validflag << endl;
        oa << node;//序列化到一个ostringstream里面  
    } 
    std::string content = os.str();//content保存了序列化后的数据。  
    muduo::StringPiece message(content);
    //codec.send(get_pointer(*tcpcli), message);
    codec.send(tcpcli, message);
    cout << "codes send finished "   << endl;
    return 0;
}

void initreaddb()
{
  std::vector<CMstNodeData> vecnode;
  ConnPool* pPool =  ConnPool::GetInstance();
  {
     sql::Connection *  pConn = pPool->GetConnection();
     if(pConn==NULL)
     {
        cout << "error  pConn  get is null "   << endl;
        return ;
     }
     ReadAllNodeToNet(pConn, vecnode );
     pPool->ReleaseConnection(pConn);

  }
}
//    std::cin.get();  
void ReadAllNodeToNet(sql::Connection * con,std::vector<CMstNodeData>& vecnode )
{
    char sqlBuf[500] = {""};

    sprintf(sqlBuf ,"select *from udevforums_major_node_bind ");

    sql::Statement * stmt = NULL;
    stmt = con->createStatement();
    if(stmt == NULL)
    {
        BOOST_LOG_TRIVIAL(info)<<"sql query   query ulord failed  ";
        cout << "query master node nodeaddr "   << endl;
    }
    stmt->execute("SET CHARSET GB2312");
    stmt->execute("USE mysql");
    CMstNodeData mstnode;
    sql::ResultSet * resultSet =  stmt->executeQuery(sqlBuf);
    int i = 0;
    while (resultSet->next()) {
        mstnode._hostname  = resultSet->getString(5);
        mstnode._txid      = resultSet->getString(6);
        mstnode._voutid    = resultSet->getInt(7);
        mstnode._hostip    = resultSet->getString(8);
        mstnode._validflag = resultSet->getInt(11);
        mstnode._licperiod = resultSet->getInt(12);
        mstnode._licence   = resultSet->getInt(13);
        vecnode.push_back(mstnode);

        uint256 txid;
        txid.SetHex(mstnode._txid);
        COutPoint mnVin = COutPoint(txid, mstnode._voutid);
        AddMasterNodeMemory(mnVin, mstnode._validflag);
        cout<<"master tx  "<< mstnode._txid << " vouid " << mstnode._voutid <<" hostname " << mstnode._hostname << " hostip  "<< mstnode._hostip <<endl;
        i++;
	std::string pubkey("89583f4a4621c64905ded004443191e3da345091");
	cout<<"certificate:" <<SignMessage(mstnode._txid, mstnode._voutid, pubkey, mstnode._licperiod)<<endl;

    }

    cout<<"total "<<i<<" record"<<endl;
    delete stmt;
    delete resultSet;

}

void  ReadMasterNodeToNet(sql::Connection * con, std::string txid, unsigned int voutid,std::vector<CMstNodeData>& vecnode)
{
    char sqlBuf[500] = {""};

    sprintf(sqlBuf ,"select *from udevforums_major_node_bind where trade_txid =\'%s\' and trade_vout_no = %d",
          txid.c_str(), voutid);

    sql::Statement * stmt = NULL;
    stmt = con->createStatement();
    if(stmt == NULL)
    {
        BOOST_LOG_TRIVIAL(info)<<"sql query" << "query ulord failed  ";
        cout << "query master node nodeaddr "   << endl;
   
    }
    stmt->execute("SET CHARSET GB2312");
    stmt->execute("USE mysql");
/*
1     `id` BIGINT (20) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
2	 `gmt_create` BIGINT (20) NOT NULL COMMENT '创建时间',
3	 `gmt_modify` BIGINT (20) NOT NULL COMMENT '修改时间',
4	 `user_id` VARCHAR (32) DEFAULT NULL,
5	 `major_node_nickname` VARCHAR (64) DEFAULT NULL COMMENT '主节点昵称',
6	 `trade_txid` VARCHAR (64) DEFAULT NULL COMMENT '1万UT交易ID',
7	 `trade_vout_no` VARCHAR (64) DEFAULT NULL COMMENT '1万UT交易ID对应的Vout序号',
8	 `ip_address` VARCHAR (64) DEFAULT NULL COMMENT '主节点IP地址',
9	 `special_code` VARCHAR (255) DEFAULT NULL COMMENT '主节点特征码',
10	 `status` INT (3) DEFAULT '0' COMMENT '状态,0:绑定中,1:绑定确认成功,2.绑定确认失败',
11	 `validflag` INT (3) DEFAULT '0' COMMENT '有效标志位,0为无效标志，1为有效，不由用户填写' 
12	 `validdate` BIGINT (20) DEFAULT '0' COMMENT '签证的有效期 validflag=1有效 必填',  
13	 `certificate` VARCHAR (255) DEFAULT NULL COMMENT '证书',
14	 `ut_addr` VARCHAR (255) DEFAULT NULL COMMENT 'Ulord地址',
15	 `remark` VARCHAR (255) DEFAULT NULL COMMENT '绑定确认失败原因',
16	 `audit_num` INT (3) NOT NULL DEFAULT '0' COMMENT '绑定确认次数',
17	 `auditor` VARCHAR (32) DEFAULT NULL COMMENT '绑定确认审核人',
18	 `gmt_audit` BIGINT (20) DEFAULT NULL COMMENT '绑定确认审核时间',
19	 `ext_info` VARCHAR (255) DEFAULT NULL COMMENT '扩展信息',
 */
    CMstNodeData mstnode;
    sql::ResultSet * resultSet =  stmt->executeQuery(sqlBuf);
    int i = 0;
    while (resultSet->next()) {
        mstnode._hostname  = resultSet->getString(5);
        mstnode._txid      = resultSet->getString(6);
        mstnode._voutid    = resultSet->getInt(7);
        mstnode._hostip    = resultSet->getString(8);
        mstnode._validflag = resultSet->getInt(11);
        mstnode._licperiod = resultSet->getInt(12);
        mstnode._licence   = resultSet->getInt(13);
        cout<<"master txid "<<  mstnode._txid << " voutid " << mstnode._voutid  << " hostname " << mstnode._hostname << " hostip "<< mstnode._hostip << " validflag " << mstnode._validflag <<endl;
        vecnode.push_back(mstnode);
        i++;
    }
    
    //BOOST_LOG_TRIVIAL(info)<<"sql query","query btcoin_hight failed  ";
    // cout << "query master node g_sqlblockheight "   << endl;

    cout<<"total "<<i<<" record"<<endl;
    delete stmt;
    delete resultSet;
}
