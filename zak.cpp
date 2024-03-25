#include <cstdio>
#include <bit>
#include <cstdlib>
#include <span>
#include <lz4.h>
#include <string_view>
#include <filesystem>
#include <comdef.h>

/* Buffers. */
namespace {
	using u8 = std::uint8_t;
	using u16 = std::uint16_t;
	using u32 = std::uint32_t;
	using u64 = std::uint64_t;

	template<typename T>
	constexpr bool IsPowerOfTwo(T x) {
		return (x != 0) && ((x & (x - 1)) == 0);
	}

	template<std::size_t Size>
	union Buffer {
		static_assert(IsPowerOfTwo(Size));

		u8  m8  [Size / sizeof(u8)];
		u16 m16 [Size / sizeof(u16)];
		u32 m32 [Size / sizeof(u32)];
		u64 m64 [Size / sizeof(u64)];
	};

	using Buffer8   = Buffer<8>;
	using Buffer16  = Buffer<16>;
	using Buffer32  = Buffer<32>;
	using Buffer64  = Buffer<64>;
}

/* Decryption. */
namespace {
	struct Salsy20Ctx {
		
		static constexpr Buffer16 s_Constant = {.m8{
			'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
		}};

		static constexpr u64 CalcArg1(size_t size) {
			return size | u64(u64(size + 1) << 32);
		}

		static constexpr u32 CalcArg2(size_t size) {
			return u32(~size);
		}
		
		Buffer64 mState;
		u64 mBlockIndex;
		Buffer32 field_48;
		u64 mArg1;
		u32 field_70;
		u64 field_78;
		Buffer16 mConstant;
		Buffer32 mKey1;
		Buffer16 mKey2;

		constexpr Salsy20Ctx(Buffer32 key, size_t size) : 
			mConstant(s_Constant),
			mArg1(CalcArg1(size)),
			field_70(CalcArg2(size)),
			field_48(key),
			mKey1(key),
			mKey2({.m32 {
				0,
				u32(0 + CalcArg1(size)),
				u32(CalcArg1(size) >> 32),
				CalcArg2(size),
			}}),
			field_78(0),
			mBlockIndex(0x40),
            mState({})
		{}

		constexpr void Decrypt(std::span<std::byte> input) {
			std::byte* start = input.data();
			std::byte* end = start + input.size();

			u32 i; // x8
			Buffer16 v5; // q0
			Buffer16 v6; // q1
			int v7; // w16
			Buffer16 v8; // q3
			u32 x5; // w14
			u32 x4; // w20
			u32 x0; // w6
			u32 x1; // w7
			u32 x12; // w12
			u32 x13; // w18
			u32 x8; // w3
			u32 x9; // w19
			u32 x7; // w5
			u32 x6; // w17
			u32 x3; // w21
			u32 x2; // w22
			u32 x14; // w4
			u32 x15; // w11
			u32 x10; // w13
			u32 x11; // w15
			u32 v25; // w6
			u32 v26; // w7
			u32 v27; // w22
			u32 v28; // w21
			int v29; // w12
			Buffer8 v30; // t2
			int v31; // w18
			int v32; // w4
			int v33; // w11
			u32 v34; // w3
			u32 v35; // w19
			u32 v36; // w13
			u32 v37; // w15
			int v38; // w20
			int v39; // w14
			int v40; // w17
			int v41; // w5
			u32 v42; // w6
			u32 v43; // w7
			u32 v44; // w22
			u32 v45; // w21
			int v46; // w12
			int v47; // w18
			int v48; // w4
			int v49; // w11
			u32 v50; // w3
			u32 v51; // w19
			u32 v52; // w13
			u32 v53; // w15
			int v54; // w20
			int v55; // w14
			int v56; // w17
			int v57; // w5
			int v58; // w6
			int v59; // w7
			int v60; // w22
			int v61; // w21
			int v62; // w11
			int v63; // w12
			int v64; // w18
			int v65; // w4
			int v66; // w13
			int v67; // w15
			int v68; // w3
			int v69; // w19
			int v70; // w14
			int v71; // w17
			int v72; // w5
			int v73; // w20
			u32 v74; // w23
			u32 v75; // w16
			u32 v76; // w7
			u32 v77; // w7
			u32 v78; // w6
			u32 v79; // w17
			u32 v80; // w17
			u32 v81; // w13
			u32 v82; // w14
			int mArg2; // w15

			if ( end )
			{
				for ( i = 0LL; i < end - start; ++i )
				{
					if ( mBlockIndex <= 0x3F )
					{
						v75 = this->mState.m8[mBlockIndex];
					}
					else
					{
						v5.m64[0] = this->mKey1.m64[2];
						v5.m64[1] = this->mKey1.m64[3];
						v6.m64[0] = this->mKey2.m64[0];
						v6.m64[1] = this->mKey2.m64[1];
						v7 = 10;
						this->mState.m32[0] = this->mConstant.m32[0];
						this->mState.m32[1] = this->mConstant.m32[1];
						this->mState.m32[2] = this->mConstant.m32[2];
						this->mState.m32[3] = this->mConstant.m32[3];
						this->mState.m32[4] = this->mKey1.m32[0];
						this->mState.m32[5] = this->mKey1.m32[1];
						this->mState.m32[6] = this->mKey1.m32[2];
						this->mState.m32[7] = this->mKey1.m32[3];
						this->mState.m32[8] = v5.m32[0];
						this->mState.m32[9] = v5.m32[1];
						this->mState.m32[10] = v5.m32[2];
						this->mState.m32[11] = v5.m32[3];
						this->mState.m32[12] = v6.m32[0];
						this->mState.m32[13] = v6.m32[1];
						this->mState.m32[14] = v6.m32[2];
						this->mState.m32[15] = v6.m32[3];
						x4 = this->mState.m32[4];
						x5 = this->mState.m32[5];
						x0 = this->mState.m32[0];
						x1 = this->mState.m32[1];
						x12 = this->mState.m32[12];
						x13 = this->mState.m32[13];
						x8 = this->mState.m32[8];
						x9 = this->mState.m32[9];
						x6 = this->mState.m32[6];
						x7 = this->mState.m32[7];
						x2 = this->mState.m32[2];
						x3 = this->mState.m32[3];
						x14 = this->mState.m32[14];
						x15 = this->mState.m32[15];
						x10 = this->mState.m32[10];
						x11 = this->mState.m32[11];
						do
						{
						v25 = x4 + x0;
						v26 = x5 + x1;
						v27 = x6 + x2;
						v28 = x7 + x3;
						v30.m32[1] = v25 ^ x12;
						v30.m32[0] = v25 ^ x12;
						v29 = v30.m64[0] >> 16;
						v30.m32[1] = v26 ^ x13;
						v30.m32[0] = v26 ^ x13;
						v31 = v30.m64[0] >> 16;
						v30.m32[1] = v27 ^ x14;
						v30.m32[0] = v27 ^ x14;
						v32 = v30.m64[0] >> 16;
						v30.m32[1] = v28 ^ x15;
						v30.m32[0] = v28 ^ x15;
						v33 = v30.m64[0] >> 16;
						v34 = v29 + x8;
						v35 = v31 + x9;
						v36 = v32 + x10;
						v37 = v33 + x11;
						v30.m32[1] = v34 ^ x4;
						v30.m32[0] = v34 ^ x4;
						v38 = v30.m64[0] >> 20;
						v30.m32[1] = v35 ^ x5;
						v30.m32[0] = v35 ^ x5;
						v39 = v30.m64[0] >> 20;
						v30.m32[1] = v36 ^ x6;
						v30.m32[0] = v36 ^ x6;
						v40 = v30.m64[0] >> 20;
						v30.m32[1] = v37 ^ x7;
						v30.m32[0] = v37 ^ x7;
						v41 = v30.m64[0] >> 20;
						v42 = v38 + v25;
						v43 = v39 + v26;
						v44 = v40 + v27;
						v45 = v41 + v28;
						v30.m32[1] = v42 ^ v29;
						v30.m32[0] = v42 ^ v29;
						v46 = v30.m64[0] >> 24;
						v30.m32[1] = v43 ^ v31;
						v30.m32[0] = v43 ^ v31;
						v47 = v30.m64[0] >> 24;
						v30.m32[1] = v44 ^ v32;
						v30.m32[0] = v44 ^ v32;
						v48 = v30.m64[0] >> 24;
						v30.m32[1] = v45 ^ v33;
						v30.m32[0] = v45 ^ v33;
						v49 = v30.m64[0] >> 24;
						v50 = v46 + v34;
						v51 = v47 + v35;
						v52 = v48 + v36;
						v53 = v49 + v37;
						v30.m32[1] = v50 ^ v38;
						v30.m32[0] = v50 ^ v38;
						v54 = v30.m64[0] >> 25;
						v30.m32[1] = v51 ^ v39;
						v30.m32[0] = v51 ^ v39;
						v55 = v30.m64[0] >> 25;
						v30.m32[1] = v52 ^ v40;
						v30.m32[0] = v52 ^ v40;
						v56 = v30.m64[0] >> 25;
						v30.m32[1] = v53 ^ v41;
						v30.m32[0] = v53 ^ v41;
						v57 = v30.m64[0] >> 25;
						v58 = v55 + v42;
						v59 = v56 + v43;
						v60 = v57 + v44;
						v61 = v54 + v45;
						v30.m32[1] = v58 ^ v49;
						v30.m32[0] = v58 ^ v49;
						v62 = v30.m64[0] >> 16;
						v30.m32[1] = v46 ^ v59;
						v30.m32[0] = v46 ^ v59;
						v63 = v30.m64[0] >> 16;
						v30.m32[1] = v47 ^ v60;
						v30.m32[0] = v47 ^ v60;
						v64 = v30.m64[0] >> 16;
						v30.m32[1] = v61 ^ v48;
						v30.m32[0] = v61 ^ v48;
						v65 = v30.m64[0] >> 16;
						v66 = v62 + v52;
						v67 = v63 + v53;
						v68 = v50 + v64;
						v69 = v65 + v51;
						v30.m32[1] = v66 ^ v55;
						v30.m32[0] = v66 ^ v55;
						v70 = v30.m64[0] >> 20;
						v30.m32[1] = v67 ^ v56;
						v30.m32[0] = v67 ^ v56;
						v71 = v30.m64[0] >> 20;
						v30.m32[1] = v68 ^ v57;
						v30.m32[0] = v68 ^ v57;
						v72 = v30.m64[0] >> 20;
						v30.m32[1] = v69 ^ v54;
						v30.m32[0] = v69 ^ v54;
						v73 = v30.m64[0] >> 20;
						x0 = v70 + v58;
						x1 = v71 + v59;
						x2 = v72 + v60;
						x3 = v73 + v61;
						v30.m32[1] = x0 ^ v62;
						v30.m32[0] = x0 ^ v62;
						x15 = v30.m64[0] >> 24;
						v30.m32[1] = x1 ^ v63;
						v30.m32[0] = x1 ^ v63;
						x12 = v30.m64[0] >> 24;
						v30.m32[1] = x2 ^ v64;
						v30.m32[0] = x2 ^ v64;
						x13 = v30.m64[0] >> 24;
						v30.m32[1] = x3 ^ v65;
						v30.m32[0] = x3 ^ v65;
						x14 = v30.m64[0] >> 24;
						x10 = x15 + v66;
						x11 = x12 + v67;
						x8 = x13 + v68;
						x9 = x14 + v69;
						v30.m32[1] = x10 ^ v70;
						v30.m32[0] = x10 ^ v70;
						x5 = v30.m64[0] >> 25;
						v30.m32[1] = x11 ^ v71;
						v30.m32[0] = x11 ^ v71;
						x6 = v30.m64[0] >> 25;
						v30.m32[1] = x8 ^ v72;
						v30.m32[0] = x8 ^ v72;
						x7 = v30.m64[0] >> 25;
						v30.m32[1] = x9 ^ v73;
						v30.m32[0] = x9 ^ v73;
						x4 = v30.m64[0] >> 25;
						--v7;
						}
						while ( v7 );
						v74 = this->mConstant.m32[1];
						v75 = this->mConstant.m32[0] + x0;
						this->mState.m32[0] = v75;
						this->mState.m32[1] = v74 + x1;
						v76 = this->mConstant.m32[3] + x3;
						this->mState.m32[2] = this->mConstant.m32[2] + x2;
						this->mState.m32[3] = v76;
						v77 = this->mKey1.m32[1];
						this->mState.m32[4] = this->mKey1.m32[0] + x4;
						this->mState.m32[5] = v77 + x5;
						v78 = this->mKey1.m32[3];
						this->mState.m32[6] = this->mKey1.m32[2] + x6;
						this->mState.m32[7] = v78 + x7;
						v79 = this->mKey1.m32[5] + x9;
						this->mState.m32[8] = this->mKey1.m32[4] + x8;
						this->mState.m32[9] = v79;
						v80 = this->mKey1.m32[7];
						this->mState.m32[10] = this->mKey1.m32[6] + x10;
						this->mState.m32[11] = v80 + x11;
						v82 = this->mKey2.m32[0];
						v81 = this->mKey2.m32[1];
						this->mState.m32[12] = v82 + x12;
						this->mState.m32[13] = v81 + x13;
						mArg2 = this->mKey2.m32[3];
						this->mState.m32[14] = this->mKey2.m32[2] + x14;
						this->mState.m32[15] = mArg2 + x15;
						this->mKey2.m32[0] = v82 + 1;
						if ( v82 == -1 )
						this->mKey2.m32[1] = v81 + 1;
						this->mBlockIndex = 0LL;
					}
					start[i] ^= static_cast<std::byte>(v75);
                    mBlockIndex++;
				}
			}
		}
	};

	struct Header {
		std::uint32_t m_MaxDecompressedSize;
		std::uint32_t m_CompressedSize;
		std::uint8_t m_Data[0];
	};
}

/* Utils. */
namespace {

	inline std::span<std::byte> ReadFile(const char* path) {
		FILE* f = fopen(path, "rb");
		if(f == nullptr) {
			printf("Failed to open \"%s\"\n", path);
			exit(1);
		}

		fseek(f, 0, SEEK_END);
		size_t size = ftell(f);
		fseek(f, 0, SEEK_SET);

		void* data = malloc(size);
		int res = fread(data, size, 1, f);
		fclose(f);

		return {reinterpret_cast<std::byte*>(data), size};
	}

	inline void WriteFile(const char* path, std::span<std::byte> data) {
		FILE* f = fopen(path, "w+");
		if(f == nullptr) {
			printf("Failed to open \"%s\"\n", path);
			exit(1);
		}

		fwrite(data.data(), 1, data.size(), f);
		fclose(f);
	}
}

static std::span<std::byte> Decompress(std::span<std::byte> input) {

	auto* outerData = reinterpret_cast<Header*>(input.data());
	auto* tmp = static_cast<Header*>(malloc(outerData->m_MaxDecompressedSize));
	printf("outerData->m_CompressedSize = %x\nouterData->m_MaxDecompressedSize = %x\n", outerData->m_CompressedSize, outerData->m_MaxDecompressedSize);
	int outerDecompSize = LZ4_decompress_safe(
		reinterpret_cast<char*>(&outerData->m_Data),
		reinterpret_cast<char*>(tmp),
		outerData->m_CompressedSize,
		outerData->m_MaxDecompressedSize
	);
	if (outerDecompSize != outerData->m_MaxDecompressedSize) {
		printf("Outer decompress fail! %d\n", outerDecompSize);
		abort();
	}

	auto* out = static_cast<std::byte*>(malloc(tmp->m_MaxDecompressedSize));
	printf("tmp->m_CompressedSize = %x\ntmp->m_MaxDecompressedSize = %x\n", tmp->m_CompressedSize, tmp->m_MaxDecompressedSize);
	int innerDecompSize = LZ4_decompress_safe(
		reinterpret_cast<char*>(&tmp->m_Data),
		reinterpret_cast<char*>(out),
		tmp->m_CompressedSize,
		tmp->m_MaxDecompressedSize
	);
	if (innerDecompSize != tmp->m_MaxDecompressedSize) {
		printf("Inner decompress fail! %d\n", innerDecompSize);
		abort();
	}

	free(tmp);
	return {out, static_cast<size_t>(innerDecompSize)};
}

/* Zak. */
namespace zak {

	struct File;

	struct Header {
		static constexpr std::uint32_t sMagic = 0x24B415A;

		std::uint32_t mMagic;
        /* Unknown? */
		char padding[4];
		std::uint32_t mFileCount;
		std::uint32_t mDataStart;

		void* End() {
			return reinterpret_cast<std::byte*>(this) + sizeof(Header);
		}

		std::byte* Data() {
			return reinterpret_cast<std::byte*>(this) + mDataStart;
		}

		File* Files() {
			return reinterpret_cast<File*>(End());
		}
	};

	struct File {
		u32 Unk;
		u32 mStrLen;
		u32 mOffset;
		u32 mSize;

		void* End() {
			return reinterpret_cast<std::byte*>(this) + sizeof(File) + mStrLen;
		}

		File* Next() {
			return reinterpret_cast<File*>(End());
		}

		std::string_view GetFileName() {
			return { reinterpret_cast<char*>(this) + sizeof(File), static_cast<size_t>(mStrLen) };
		}
	};
}

static constexpr Buffer32 s_Key = { .m8 {
	0x62, 0x1F, 0x1C, 0x38, 0xF1, 0x63, 0x30, 0x16, 0xBC, 0x51, 0x49, 0x47, 0xBE, 0xC1, 0x58, 0xDB,
	0xF2, 0xC0, 0x8C, 0x6F, 0x45, 0xB1, 0xCF, 0xEC, 0x04, 0x9A, 0xA1, 0x33, 0xBB, 0xCF, 0x90, 0xC5
}};

int main(int argc, char** argv) {
	if(argc != 3) {
		printf("%s: [input] [output]\n", argv[0]);
		return 0;
	}

	const char* inputPath = argv[1];
	std::filesystem::path outputPath(argv[2]);

	printf("Reading...\n");
	auto input = ReadFile(inputPath);

	printf("Decrypting...\n");
    Salsy20Ctx ctx(s_Key, input.size());
	ctx.Decrypt(input);

    printf("Writing compressed zak...\n");
	create_directories(outputPath);
    WriteFile((outputPath.string() + "/compressed_decrypted.zak").c_str(), input);

	printf("Decompressing...\n");
	auto zakData = Decompress(input);
	
	auto header = reinterpret_cast<zak::Header*>(zakData.data());
	if(header->mMagic == zak::Header::sMagic) {
		printf("Extracting...\n");
		auto file = header->Files();
		for(int i = 0; i < header->mFileCount; i++) {
			auto str = std::string(file->GetFileName());
			printf("Writing %s...\n", str.c_str());

			auto path = outputPath / str;
			auto newpath =  outputPath.string()  + "/" + str;
            create_directories(path.parent_path());
			
			auto fileData = std::span<std::byte> { header->Data() + file->mOffset, file->mSize };
			WriteFile(newpath.c_str(), fileData);

			file = file->Next();
		}
	} else {
		printf("Decrypted file seems corrupt. Skipping extraction...\n");
	}

	printf("Writing decompressed zak...\n");
	WriteFile((outputPath.string() + "/compressed_decrypted.zak").c_str(), zakData);

	free(zakData.data());
	free(input.data());
    
    return 0;
}
