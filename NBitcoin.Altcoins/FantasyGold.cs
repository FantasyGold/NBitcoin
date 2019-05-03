using System;
using System.Linq;
using System.Text;
using NBitcoin.Altcoins.Nist5;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;

namespace NBitcoin.Altcoins
{
	// https://github.com/FantasyGold/FantasyGold-Core/blob/master/src/chainparams.cpp
	public class FantasyGold : NetworkSetBase
	{
		public static FantasyGold Instance { get; } = new FantasyGold();

		public override string CryptoCode => "FGC";

		private FantasyGold()
		{
		}

		public class FantasyGoldConsensusFactory : ConsensusFactory
		{
			private FantasyGoldConsensusFactory()
			{
			}

			public static FantasyGoldConsensusFactory Instance { get; } = new FantasyGoldConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new FantasyGoldBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new FantasyGoldBlock(new FantasyGoldBlockHeader());
			}
		}


#pragma warning disable CS0618 // Type or member is obsolete
		public class FantasyGoldBlockHeader : BlockHeader
		{
			// blob
			private static byte[] CalculateHash(byte[] data, int offset, int count)
			{
				return new Nist5().ComputeBytes(data.Skip(offset).Take(count).ToArray());
			}

			protected override HashStreamBase CreateHashStream()
			{
				return BufferedHashStream.CreateFrom(CalculateHash);
			}
		}

		public class FantasyGoldBlock : Block
		{
#pragma warning disable CS0612 // Type or member is obsolete
			public FantasyGoldBlock(FantasyGoldBlockHeader h) : base(h)
#pragma warning restore CS0612 // Type or member is obsolete
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return Instance.Mainnet.Consensus.ConsensusFactory;
			}
		}
#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("FantasyGold", new FolderName() { TestnetFolder = "testnet4" });
		}

		static uint256 GetPoWHash(BlockHeader header)
		{
			var headerBytes = header.ToBytes();
			var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
			return new uint256(h);
		}

		protected override NetworkBuilder CreateMainnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				//SubsidyHalvingInterval = 700800,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000006b85859195cd62b57d137bba5871588d8f05cecc5fa21673e4c894e8997"),
				PowLimit = new Target(new uint256("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x0000000004526e78914301cb0a008801a9219ed07c659860404bfafc6f983701"),
				PowTargetTimespan = TimeSpan.FromSeconds(90),
				PowTargetSpacing = TimeSpan.FromSeconds(90),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 66,
				PowNoRetargeting = false,
				LastPOWBlock = 43200;

			ConsensusFactory = FantasyGoldConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 35 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 18 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 1 + 212 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x46, 0x53, 0x47, 0x4D })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x66, 0x73, 0x67, 0x70 })
			.SetMagic(0x424D4954)
			.SetPort(57810)
			.SetRPCPort(57814)
			.SetName("FantasyGold-main")
			.AddAlias("FantasyGold-mainnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("seeder.fantasygold.co", "seeder.fantasygold.co")
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000002955549528d0bda6cf2910ab9e6d62690c9be41cc79a624743cbf57ecb4ef57fe94ff59ffff0f1ed17e0f000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4204ffff001d01043a464f5242455320415547203230203230313320546865202437302042696c6c696f6e2046616e7461737920466f6f7462616c6c204d61726b6574ffffffff0100f9029500000000434104243e8da79e117dba99d89a2da6ed761af43175227d19caaffea72398514962af9701478a69410b8158e190ae36d50a1f7325eba3df9559ad345db0cb72bfe2e2ac0000000054494d42b3000000030000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			var res = builder.SetConsensus(new Consensus()
			{
				//SubsidyHalvingInterval = 56600,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 100,
				BIP34Hash = new uint256("0x000005b218ee50a90d18144376a07d8fa5e2477b234c1a7df54fa29229ecf96c"),
				PowLimit = new Target(new uint256("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x000000000000000000000000000000000000000000000000000000060e06d35d"),
				PowTargetTimespan = TimeSpan.FromSeconds(24 * 60 * 60;),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 15,
				PowNoRetargeting = false,
				ConsensusFactory = FantasyGoldConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 65 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 12 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 1 + 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x3a, 0x80, 0x61, 0xa0 })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x3a, 0x80, 0x58, 0x37 })
			.SetMagic(0x64350241)
			.SetPort(58806)
			.SetRPCPort(58807)
			.SetName("FantasyGold-test")
			.AddAlias("FantasyGold-testnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("dns1.fantasygold.co", "dns1.fantasygold.co")
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000002955549528d0bda6cf2910ab9e6d62690c9be41cc79a624743cbf57ecb4ef57fe94ff59ffff0f1ed17e0f000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4204ffff001d01043a464f5242455320415547203230203230313320546865202437302042696c6c696f6e2046616e7461737920466f6f7462616c6c204d61726b6574ffffffff0100f9029500000000434104243e8da79e117dba99d89a2da6ed761af43175227d19caaffea72398514962af9701478a69410b8158e190ae36d50a1f7325eba3df9559ad345db0cb72bfe2e2ac0000000054494d42b3000000030000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				//SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 100,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x0000000000000000000000000000000000000000000000000000000000000000"),
				PowTargetTimespan = TimeSpan.FromSeconds(24 * 60 * 60;),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 15,
				PowNoRetargeting = true,
				ConsensusFactory = FantasyGoldConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x3a, 0x80, 0x61, 0xa0 })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x3a, 0x80, 0x58, 0x37 })
			.SetMagic(0xac7ecfa1)
			.SetPort(59806)
			.SetRPCPort(59807)
			.SetName("FantasyGold-reg")
			.AddAlias("FantasyGold-regtest")
			.AddDNSSeeds(new DNSSeedData[0])
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000002955549528d0bda6cf2910ab9e6d62690c9be41cc79a624743cbf57ecb4ef57fe94ff59ffff0f1ed17e0f000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4204ffff001d01043a464f5242455320415547203230203230313320546865202437302042696c6c696f6e2046616e7461737920466f6f7462616c6c204d61726b6574ffffffff0100f9029500000000434104243e8da79e117dba99d89a2da6ed761af43175227d19caaffea72398514962af9701478a69410b8158e190ae36d50a1f7325eba3df9559ad345db0cb72bfe2e2ac0000000054494d42b3000000030000");
			return builder;
		}
	}
}