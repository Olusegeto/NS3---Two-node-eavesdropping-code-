
#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/wifi-module.h"
#include "ns3/config-store-module.h"
 
#include <set>
#include <map>
#include "my-colors.h"

using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE ("manet-routing-compare");

uint32_t total_sniffed_packets = 0;

std::set<uint32_t> sniffed_sequence_set;

/* A map is a "collection" (like arrays or vector), where the index can be of any data type, not just integers.
The index type of my map is Ipv4Address.
The type of each element of the map is a set of uint32_t
*/
std::map <ns3::Ipv4Address, std::set<uint32_t>> sniffed_packets;

uint32_t total_dropped_phy = 0;

uint32_t app_0_tx = 0;
uint32_t app_1_tx = 0;

void App0Tx (std::string context, Ptr< const Packet > packet)
{
  app_0_tx++;
}
void App1Tx (std::string context, Ptr< const Packet > packet)
{
  app_1_tx++;
}
uint32_t actually_began_tx = 0;
uint32_t tx_dropped = 0;
void PhyTxBeginTrace (std::string context, Ptr< const Packet > packet, double txPowerW)
{
  if (packet->GetSize()>100)
    actually_began_tx++;
}
void PhyTxDrop (std::string context, Ptr <const Packet> packet)
{
  
  NS_LOG_UNCOND (CYAN_CODE << Now().GetSeconds() << " : " << context << END_CODE);
  tx_dropped++;
}
void ChangePower (uint32_t node_id, double power)
{
  Config::Set ("/NodeList/" + std::to_string(node_id) + "/DeviceList/*/$ns3::WifiNetDevice/Phy/TxPowerStart", DoubleValue(power));
  Config::Set ("/NodeList/" + std::to_string(node_id) + "/DeviceList/*/$ns3::WifiNetDevice/Phy/TxPowerEnd", DoubleValue(power));
 
}
void PhyRxDrop (std::string context, Ptr<const Packet> packet, WifiPhyRxfailureReason reason)
{
  NS_LOG_UNCOND("" << RED_CODE << context << " : " << reason << END_CODE);
  //NS_LOG_UNCOND( packet->ToString() << END_CODE);
  total_dropped_phy++;
}
void MacTxDrop(std::string context, Ptr< const Packet> packet)
{
  NS_LOG_UNCOND (PURPLE_CODE << Now().GetSeconds() << " : " << context << END_CODE);
}
void QueueDropTrace(std::string context, Ptr<const WifiMacQueueItem> item)
{
  NS_LOG_UNCOND (YELLOW_CODE << Now().GetSeconds() << context << " : " << END_CODE << "Queue Dropped soomething" );
}

void 
MaliciousListen(std::string context, Ptr<const Packet> packet, uint16_t channelFreqMhz, WifiTxVector txVector, MpduInfo aMpdu, SignalNoiseDbm signalNoise, uint16_t staId)
{
  //NS_LOG_UNCOND ("=============== Malicious Listen ======================= " << context);
  //NS_LOG_UNCOND (packet->ToString());

  //ns3::WifiMacHeader (DATA ToDS=0, FromDS=0, MoreFrag=0, Retry=1, MoreData=0 Duration/ID=213us, DA=00:00:00:00:00:02, SA=00:00:00:00:00:01, BSSID=00:00:00:00:00:01, FragNumber=0, SeqNumber=255) ns3::LlcSnapHeader (type 0x800) ns3::Ipv4Header (tos 0x0 DSCP Default ECN Not-ECT ttl 64 id 254 protocol 17 offset (bytes) 0 flags [none] length: 128 10.1.1.1 > 10.1.1.2) ns3::UdpHeader (length: 108 49153 > 9) ns3::SeqTsSizeHeader ((size=100) AND (seq=254 time=+199.964s)) Payload (size=80) ns3::WifiMacTrailer ()

  Ptr <Packet> packet_copy = packet->Copy ();
  WifiMacHeader whdr;
  LlcSnapHeader snap;
  Ipv4Header ip4;
  UdpHeader udp;
  SeqTsSizeHeader seqHdr;
  if (packet_copy->RemoveHeader (whdr))
  {
    

    //NS_LOG_UNCOND ("Source MAC : " << whdr.GetAddr2());
    //NS_LOG_UNCOND ("Destination MAC: " << whdr.GetAddr1());
    if (whdr.IsData ())
    {
          NS_LOG_UNCOND (Now().GetSeconds() << " : sniffing Seq No.: " << whdr.GetSequenceNumber() 
                   << " Freuqency is " << channelFreqMhz << " MHz" << " Mode: " << txVector.GetMode());
          NS_LOG_UNCOND (packet->ToString());

      //NS_LOG_UNCOND ("Data Packet. Size=" << packet->GetSize());
      if (packet_copy->RemoveHeader (snap))
      {
        if (packet_copy->RemoveHeader (ip4))
        {
          if (packet_copy->RemoveHeader (udp))
          {
            //NS_LOG_UNCOND ("Content: " << packet_copy->ToString());
            if (packet_copy->RemoveHeader(seqHdr))
            {
              NS_LOG_UNCOND (Now().GetSeconds() << " Rx packet id - " << seqHdr.GetSeq());
              //sniffed_sequence_set.insert (seqHdr.GetSeq());

              Ipv4Address source_ip = ip4.GetSource ();
              sniffed_packets [source_ip].insert (seqHdr.GetSeq());

            }

            
          }
        }
      }
      else
      {
        NS_LOG_UNCOND (packet->ToString()); 
      }
    }
  }

}

class RoutingExperiment
{
public:
  RoutingExperiment ();
  void Run (int nSinks, double txp, std::string CSVfileName);
  //static void SetMACParam (ns3::NetDeviceContainer & devices,
  //                                 int slotDistance);
  std::string CommandSetup (int argc, char **argv);

private:
  Ptr<Socket> SetupPacketReceive (Ipv4Address addr, Ptr<Node> node);
  void ReceivePacket (Ptr<Socket> socket);
  void CheckThroughput ();

  uint32_t port;
  uint32_t bytesTotal;
  uint32_t packetsReceived;

  std::string m_CSVfileName;
  int m_nSinks;
  std::string m_protocolName;
  double m_txp;
  bool m_traceMobility;
  uint32_t m_protocol;
};

RoutingExperiment::RoutingExperiment ()
  : port (9999),
    bytesTotal (0),
    packetsReceived (0),
    m_CSVfileName ("manet-routing.output.csv"),
    m_traceMobility (false),
    m_protocol (2) // AODV
{
}

static inline std::string
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();

  if (InetSocketAddress::IsMatchingType (senderAddress))
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress);
      oss << " received one packet from " << addr.GetIpv4 ();
    }
  else
    {
      oss << " received one packet!";
    }
  return oss.str ();
}

void
RoutingExperiment::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address senderAddress;
  while ((packet = socket->RecvFrom (senderAddress)))
    {
      bytesTotal += packet->GetSize ();
      packetsReceived += 1;
      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
    }
}

void
RoutingExperiment::CheckThroughput ()
{
  double kbs = (bytesTotal * 8.0) / 1000;
  bytesTotal = 0;

  std::ofstream out (m_CSVfileName.c_str (), std::ios::app);

  out << (Simulator::Now ()).GetSeconds () << ","
      << kbs << ","

      << packetsReceived << ","
      << m_nSinks << ","
      << m_protocolName << ","
      << m_txp << ""
      << std::endl;

  out.close ();
  packetsReceived = 0;
  Simulator::Schedule (Seconds (1.0), &RoutingExperiment::CheckThroughput, this);
}

Ptr<Socket>
RoutingExperiment::SetupPacketReceive (Ipv4Address addr, Ptr<Node> node)
{
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback (&RoutingExperiment::ReceivePacket, this));

  return sink;
}

std::string
RoutingExperiment::CommandSetup (int argc, char **argv)
{
  uint64_t run = 1;
  uint64_t seed = 1;

  CommandLine cmd (__FILE__);
  cmd.AddValue ("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
  cmd.AddValue ("traceMobility", "Enable mobility tracing", m_traceMobility);
  cmd.AddValue ("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol);
  
  cmd.AddValue ("run", "RNG run value", run);
  cmd.AddValue ("seed", "Seed value for RNG", seed);

  
  cmd.Parse (argc, argv);

  
  RngSeedManager::SetRun (run);
  RngSeedManager::SetSeed (seed);

  return m_CSVfileName;
}

int
main (int argc, char *argv[])
{
 

  RoutingExperiment experiment;
  std::string CSVfileName = experiment.CommandSetup (argc,argv);

  //blank out the last output file and write the column headers
  std::ofstream out (CSVfileName.c_str ());
  out << "SimulationSecond," <<
  "ReceiveRate," <<
  "PacketsReceived," <<
  "NumberOfSinks," <<
  "RoutingProtocol," <<
  "TransmissionPower" <<
  std::endl;
  out.close ();

  int nSinks = 1;
  double txp = 7.5; // was 27.5

  experiment.Run (nSinks, txp, CSVfileName);
}

void
RoutingExperiment::Run (int nSinks, double txp, std::string CSVfileName)
{
  Packet::EnablePrinting ();
  m_nSinks = nSinks;
  m_txp = txp;
  m_CSVfileName = CSVfileName;

  int nWifis = 3; // modified 

  double TotalTime = 101.0;
  std::string rate ("1Mbps");
  std::string phyMode ("DsssRate11Mbps");
  std::string tr_name ("manet-routing-compare");
  int nodeSpeed = 0; //in m/s
  int nodePause = 0; //in s
  m_protocolName = "protocol";
  uint32_t SentPackets = 0;
  uint32_t ReceivedPackets = 0;
  uint32_t LostPackets = 0; 

  Config::SetDefault  ("ns3::OnOffApplication::PacketSize",StringValue ("64"));
  Config::SetDefault ("ns3::OnOffApplication::DataRate",  StringValue (rate));

  //Set Non-unicastMode rate to unicast mode
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));

  NodeContainer adhocNodes;
  adhocNodes.Create (nWifis);

  // setting up wifi phy and channel using helpers

  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211b); //   WIFI_STANDARD_80211n_2_4GHZ

  YansWifiPhyHelper wifiPhy;
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue(2.412e+09));
  //wifiChannel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel");
  //wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel");

  /*
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                                 "Exponent", DoubleValue(3.0),
                                 "ReferenceDistance", DoubleValue(1.0),
                                 "ReferenceLoss", DoubleValue(46.6777));
  */
  /*
  Ptr<LogDistancePropagationLossModel> lossModel = CreateObject<LogDistancePropagationLossModel> ();   
  lossModel->SetPathLossExponent (3.0);   
  lossModel->SetReference (1, 46.6777);   
  */

  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a mac and disable rate control
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));

  wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));
  // added 
  wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  
  wifiMac.SetType ("ns3::AdhocWifiMac");
 
  NetDeviceContainer adhocDevices = wifi.Install (wifiPhy, wifiMac, adhocNodes);
  wifiPhy.EnablePcap("power-levels", adhocDevices,  true);

 
  MobilityHelper mobilityAdhoc;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 0.0, 0.0));   // was ZERO
  positionAlloc->Add (Vector (100.0, 0.0, 0.0)); // was 100.0, 
  positionAlloc->Add (Vector (50, 0.0, 0.0));    // was 
  mobilityAdhoc.SetPositionAllocator (positionAlloc);
  mobilityAdhoc.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobilityAdhoc.Install (adhocNodes);

  NodeContainer senderReceverNodes;
  senderReceverNodes.Add (adhocNodes.Get (0));
  senderReceverNodes.Add (adhocNodes.Get (1));
  


  //InternetStackHelper internet;
  //internet.Install (adhocNodes);
  
 

  AodvHelper aodv;
  OlsrHelper olsr;
  DsdvHelper dsdv;
  DsrHelper dsr;
  DsrMainHelper dsrMain;
  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;
  internet.Install (adhocNodes);


  switch (m_protocol)
    {
    case 1:
      list.Add (olsr, 100);
      m_protocolName = "OLSR";
      break;
    case 2:
      list.Add (aodv, 100);
      m_protocolName = "AODV";
      break;
    case 3:
      list.Add (dsdv, 100);
      m_protocolName = "DSDV";
      break;
    case 4:
      m_protocolName = "DSR";
      break;
    default:
      NS_FATAL_ERROR ("No such protocol:" << m_protocol);
    }
 
  NS_LOG_INFO ("assigning ip address");

  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer adhocInterfaces;
  adhocInterfaces = addressAdhoc.Assign (adhocDevices);

  //Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // default data rate is 500000bps
  OnOffHelper onoff1 ("ns3::UdpSocketFactory",Address ());
  onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

  Ptr<Socket> sink = SetupPacketReceive (adhocInterfaces.GetAddress (0), adhocNodes.Get (0));

  AddressValue remoteAddress (InetSocketAddress (adhocInterfaces.GetAddress (0), port));
  onoff1.SetAttribute ("Remote", remoteAddress);
  onoff1.SetAttribute ("EnableSeqTsSizeHeader", BooleanValue(true));
  onoff1.SetAttribute ("PacketSize", UintegerValue (100));
  //onoff1.SetAttribute ("DataRate", StringValue ("1Kbps"));

  Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
  ApplicationContainer temp = onoff1.Install (adhocNodes.Get (1));
  temp.Start (Seconds (var->GetValue (100.0,101.0)));
  temp.Stop (Seconds (TotalTime));



  OnOffHelper onoff2 ("ns3::UdpSocketFactory",Address ());
  onoff2.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff2.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
  
  Ptr<Socket> sink2 = SetupPacketReceive (adhocInterfaces.GetAddress (1), adhocNodes.Get (1));

  AddressValue remoteAddress2 (InetSocketAddress (adhocInterfaces.GetAddress (1), port));
  onoff2.SetAttribute ("Remote", remoteAddress2);
  onoff2.SetAttribute ("EnableSeqTsSizeHeader", BooleanValue(true));
  onoff2.SetAttribute ("PacketSize", UintegerValue (100));


  Ptr<UniformRandomVariable> var1 = CreateObject<UniformRandomVariable> ();
  ApplicationContainer temp1 = onoff2.Install (adhocNodes.Get (0));
  temp1.Start (Seconds (var->GetValue (100.0,101.0)));
  temp1.Stop (Seconds (TotalTime));


  for (uint32_t i=0; i<temp.GetN(); i++)
  {
    NS_LOG_UNCOND ("Application " << i << " is of type: " << temp.Get(i)->GetInstanceTypeId());
  }

  Packet::EnablePrinting ();

  Config::Connect ("/NodeList/2/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferRx", MakeCallback (&MaliciousListen));

  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback (&PhyRxDrop));

  Config::Connect ("/NodeList/0/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin", MakeCallback (&PhyTxBeginTrace));
  Config::Connect ("/NodeList/0/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback (&PhyTxDrop));



  Config::Connect ("/NodeList/0/ApplicationList/*/$ns3::OnOffApplication/Tx", MakeCallback (&App0Tx));
  Config::Connect ("/NodeList/1/ApplicationList/*/$ns3::OnOffApplication/Tx", MakeCallback (&App1Tx));

  //Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/Txop/Queue/Drop");

  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTxDrop", MakeCallback(&MacTxDrop));

  Config::Connect ("/NodeList/1/DeviceList/*/$ns3::WifiNetDevice/Mac/*/Queue/Drop", MakeCallback(&QueueDropTrace));

  std::stringstream ss;
  ss << nWifis;
  std::string nodes = ss.str ();

  std::stringstream ss2;
  ss2 << nodeSpeed;
  std::string sNodeSpeed = ss2.str ();

  std::stringstream ss3;
  ss3 << nodePause;
  std::string sNodePause = ss3.str ();

  std::stringstream ss4;
  ss4 << rate;
  std::string sRate = ss4.str ();

  //NS_LOG_INFO ("Configure Tracing.");
  //tr_name = tr_name + "_" + m_protocolName +"_" + nodes + "nodes_" + sNodeSpeed + "speed_" + sNodePause + "pause_" + sRate + "rate";

  //AsciiTraceHelper ascii;
  //Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream ( (tr_name + ".tr").c_str());
  //wifiPhy.EnableAsciiAll (osw);
  AsciiTraceHelper ascii;
  MobilityHelper::EnableAsciiAll (ascii.CreateFileStream (tr_name + ".mob"));

  //Ptr<FlowMonitor> flowmon;
  //FlowMonitorHelper flowmonHelper;
  //flowmon = flowmonHelper.InstallAll ();

 
  //Config::Set ("/NodeList/1/DeviceList/*/$ns3::WifiNetDevice/Phy/TxPowerStart", DoubleValue(30.0));
  //Config::Set ("/NodeList/1/DeviceList/*/$ns3::WifiNetDevice/Phy/TxPowerEnd", DoubleValue(30.0));
  // or by putting the code inside a function

  //ChangePower (2, 0); // changing Tx power befor starting simulation for node 1 to 0 dBm
  Simulator::Schedule (Seconds(100), &ChangePower, 0, 33); // anytime during simulation for node 1 to 33 dBm

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();

  NS_LOG_INFO ("Run Simulation.");

  CheckThroughput ();

  Simulator::Stop (Seconds (TotalTime)); 
  Simulator::Run ();

int j=0;
float AvgThroughput = 0;
Time Jitter;
Time Delay;

Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();

  uint32_t total_sent_from0 = 0;
  uint32_t total_sent_from1 = 0;
  uint32_t total_received_by0 = 0;
  uint32_t total_received_by1 = 0;
  
  

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);

    if (j==0)
    {
      total_sent_from0   = iter->second.txPackets;
      total_received_by0 = iter->second.rxPackets;
    }
    else if (j==1)
    {
      total_sent_from1   = iter->second.txPackets;
      total_received_by1 = iter->second.rxPackets;
    }

NS_LOG_UNCOND("----Flow ID:" <<iter->first);
NS_LOG_UNCOND("Src Addr" <<t.sourceAddress << "Dst Addr "<< t.destinationAddress);
//NS_LOG_UNCOND("Src Addr1" << t.sourceAddress.positionAlloc << "Dst Addr1"<< t.destinationAddress.positionAlloc);

NS_LOG_UNCOND("Sent Packets=" <<iter->second.txPackets);
NS_LOG_UNCOND("Received Packets =" <<iter->second.rxPackets);
NS_LOG_UNCOND("Lost Packets =" << iter->second.txPackets - iter->second.rxPackets);
NS_LOG_UNCOND("Packet delivery ratio =" <<iter->second.rxPackets*100.0/iter->second.txPackets << "%");
NS_LOG_UNCOND("Packet loss ratio =" << (iter->second.txPackets-iter->second.rxPackets)*100.0/iter->second.txPackets << "%");
NS_LOG_UNCOND("Delay =" <<iter->second.delaySum);
NS_LOG_UNCOND("Jitter =" <<iter->second.jitterSum);
NS_LOG_UNCOND("Throughput =" <<iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/1024<<"Kbps");

SentPackets = SentPackets +(iter->second.txPackets);
ReceivedPackets = ReceivedPackets + (iter->second.rxPackets);
LostPackets = LostPackets + (iter->second.txPackets - iter->second.rxPackets);
AvgThroughput = AvgThroughput + (iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/1024);
Delay = Delay + (iter->second.delaySum);
Jitter = Jitter + (iter->second.jitterSum);

j = j + 1;

}


NS_LOG_UNCOND (BLUE_CODE << "Actual Lost Flow 1: " << END_CODE << (total_sent_from0 - total_received_by1));
NS_LOG_UNCOND (BLUE_CODE << "Actual Lost Flow 2: " << END_CODE << (total_sent_from1 - total_received_by0));

/*
 uint32_t total_sent_from0 = 0;
  uint32_t total_sent_from1 = 0;
  uint32_t total_received_by0 = 0;
  uint32_t total_received_by1 = 0;
*/
NS_LOG_UNCOND (BOLD_CODE << "total_sent_from0 : " << END_CODE << total_sent_from0);
NS_LOG_UNCOND (BOLD_CODE << "total_sent_from1 : " << END_CODE<< total_sent_from1);
NS_LOG_UNCOND (BOLD_CODE << "total_received_by0 : " << END_CODE << total_received_by0);
NS_LOG_UNCOND (BOLD_CODE << "total_received_by1 : " << END_CODE << total_received_by1);


AvgThroughput = AvgThroughput/j;
NS_LOG_UNCOND("--------Total Results of the simulation----------"<<std::endl);
NS_LOG_UNCOND("Total sent packets  =" << SentPackets);
NS_LOG_UNCOND("Total Received Packets =" << ReceivedPackets);
NS_LOG_UNCOND("Total Lost Packets =" << LostPackets);
NS_LOG_UNCOND("Packet Loss ratio =" << ((LostPackets*100.0)/SentPackets)<< "%");
NS_LOG_UNCOND("Packet delivery ratio =" << ((ReceivedPackets*100.0)/SentPackets)<< "%");
NS_LOG_UNCOND("Average Throughput =" << AvgThroughput<< "Kbps");
NS_LOG_UNCOND("End to End Delay =" << Delay);
NS_LOG_UNCOND("End to End Jitter delay =" << Jitter);
NS_LOG_UNCOND("Total Flod id " << j);
monitor->SerializeToXmlFile("manet-routing.xml", true, true);

//NS_LOG_UNCOND ("Total Sniffed is: " << sniffed_sequence_set.size());
  //flowmon->SerializeToXmlFile ((tr_name + ".flowmon").c_str(), false, false);


std::map <ns3::Ipv4Address, std::set<uint32_t>>::iterator it;


for (it = sniffed_packets.begin(); it != sniffed_packets.end(); it++)
{
  NS_LOG_UNCOND ("Unique sniffed packets from IP " << it->first << " : " << it->second.size() << " packets");
}

NS_LOG_UNCOND (RED_CODE << "Total dropped by PHY in ALL nodes: " << END_CODE << total_dropped_phy);

NS_LOG_UNCOND (GREEN_CODE << BOLD_CODE << "App 0 traced Tx packets: " << END_CODE << app_0_tx << " packets");
NS_LOG_UNCOND (GREEN_CODE << BOLD_CODE << "App 1 traced Tx packets: " << END_CODE << app_1_tx << " packets");

NS_LOG_UNCOND (PURPLE_CODE << "Actually began TX from node 0 : " << END_CODE << actually_began_tx);
NS_LOG_UNCOND (PURPLE_CODE << "PHY TX dropped : " << END_CODE << tx_dropped);

  Simulator::Destroy ();
}

