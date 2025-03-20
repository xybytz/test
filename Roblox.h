#pragma once

#include <Windows.h>
#include <vector>

#include "zstd.h"
#include "xxhash.h"

#include "BytecodeBuilder.h"
#include "BytecodeUtils.h"
#include "Compiler.h"

using JobOriginalVF = uintptr_t(__fastcall*)(uintptr_t A1, uintptr_t A2, uintptr_t A3);

static JobOriginalVF OriginalVF = {};
static std::vector<std::string> ScriptQueue;

class bytecode_encoder_t : public Luau::BytecodeEncoder {
	inline void encode(uint32_t* data, size_t count) override {
		for (auto i = 0u; i < count;) {
			auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
			i += Luau::getOpLength(LuauOpcode(opcode));
			opcode *= 227;
		}
	}
};

std::string Compress(const std::string Bytecode) {
    size_t DataSize = Bytecode.size();
    size_t MaxSize = ZSTD_compressBound(DataSize);
    std::vector<char> Buffer(MaxSize + 8);

    memcpy(Buffer.data(), "RSB1", 4);
    memcpy(Buffer.data() + 4, &DataSize, sizeof(DataSize));

    size_t CompressedSize = ZSTD_compress(Buffer.data() + 8, MaxSize, Bytecode.data(), DataSize, ZSTD_maxCLevel());
    size_t TotalSize = CompressedSize + 8;

    uint32_t Key = XXH32(Buffer.data(), TotalSize, 42);
    uint8_t* KeyBytes = (uint8_t*)&Key;

    for (size_t i = 0; i < TotalSize; ++i) Buffer[i] ^= KeyBytes[i % 4] + i * 41;

    return std::string(Buffer.data(), TotalSize);
}

std::string Compile(const std::string& source)
{
    static bytecode_encoder_t encoder = bytecode_encoder_t();
    const std::string bytecode = Luau::compile(source, {}, {}, &encoder);

    if (bytecode[0] == '\0') {
        std::string bytecodeP = bytecode;
        bytecodeP.erase(std::remove(bytecodeP.begin(), bytecodeP.end(), '\0'), bytecodeP.end());
    }

    return Compress(bytecode);
}

// Updated for version-2b67309334b54dab
// Do you need updated offsets ? https://discord.gg/RhsMe6fnb7

#define REBASE(x) x + (uintptr_t)(GetModuleHandleA(nullptr));

uintptr_t state;

uintptr_t maxCaps = ~0ULL;

namespace offsets
{
	const uintptr_t JobToScriptContext = 0x1F8;
	const uintptr_t jobStart = 0x1D0;
	const uintptr_t jobEnd = 0x1D8;
	const uintptr_t jobName = 0x90;
	const uintptr_t getGlobalOffset = 0x130;
	const uintptr_t decryptStateOffset = 0x88;
}

namespace internalOffsets
{
	const uintptr_t Print = REBASE(0x15C9CD0);
	const uintptr_t TaskDefer = REBASE(0x1081760);
	const uintptr_t LuaVMLoad = REBASE(0xC5CA50);
	const uintptr_t GetGlobalState = REBASE(0xEA35D0);
	const uintptr_t DecryptLuaState = REBASE(0xC59A30);
	const uintptr_t RawScheduler = REBASE(0x627D908);
}

namespace functions
{
	uintptr_t getScheduler()
	{
		return *(uintptr_t*)(internalOffsets::RawScheduler);
	}

	void settop(uintptr_t state)
	{
		*(uintptr_t*)(state + 0x8) -= 0x10;
	}

	using _Print = uintptr_t(__fastcall*)(uintptr_t, const char*, ...);
	auto Print = (_Print)(internalOffsets::Print);

	using _GetGlobalState = uintptr_t(__fastcall*)(uintptr_t, uintptr_t*, uintptr_t*);
	auto GetGlobalState = (_GetGlobalState)(internalOffsets::GetGlobalState);

	using _DecryptState = uintptr_t(__fastcall*)(uintptr_t);
	auto DecryptState = (_DecryptState)(internalOffsets::DecryptLuaState);

	using _LuaVMLoad = int(__fastcall*)(uintptr_t, void*, const char*, int);
	auto LuaVMLoad = (_LuaVMLoad)(internalOffsets::LuaVMLoad);

	using _TaskDefer = uintptr_t(__fastcall*)(uintptr_t);
	auto TaskDefer = (_TaskDefer)(internalOffsets::TaskDefer);

	void setIdentity(uintptr_t state, uintptr_t level, uintptr_t caps)
	{
		uintptr_t userdata = *(uintptr_t*)(state + 0x78);

		uintptr_t* identity = (uintptr_t*)(userdata + 0x30);
		uintptr_t* capability = (uintptr_t*)(userdata + 0x48);

		*identity = level;
		*capability = caps;
	}
}

namespace scheduler
{
	std::vector<uintptr_t> getJobs()
	{
		std::vector<uintptr_t> jobs;

		uintptr_t scheduler = functions::getScheduler();

		uintptr_t start = *(uintptr_t*)(scheduler + offsets::jobStart);
		uintptr_t end = *(uintptr_t*)(scheduler + offsets::jobEnd);

		for (auto i = start; i < end; i+=0x10)
		{
			jobs.push_back(*(uintptr_t*)i);
		}

		return jobs;
	}

	uintptr_t getJobByName(std::string name)
	{
		for (auto job : scheduler::getJobs())
		{
			std::string jobName = *(std::string*)(job + offsets::jobName);

			if (jobName == name)
			{
				return job;
			}
		}

		return 0;
	}

	uintptr_t getScriptContext()
	{
		auto whsj = getJobByName("WaitingHybridScriptsJob");
		auto scriptContext = *(uintptr_t*)(whsj + offsets::JobToScriptContext);

		return scriptContext;
	}
}

namespace executor
{
	void executeScript(std::string script)
	{
		auto compiledAndCompressed = Compile(script);

		if (functions::LuaVMLoad(state, &compiledAndCompressed, "=Executor", 0) != 0)
		{
			functions::Print(3LL, "Error while executing...");
			functions::settop(state);
			return;
		}

		functions::TaskDefer(state);
		functions::settop(state);
		return;
	}

	uintptr_t Cycle(uintptr_t A1, uintptr_t A2, uintptr_t A3) {
		if (!state) return OriginalVF(A1, A2, A3);

		if (!ScriptQueue.empty()) {
			std::string Script = ScriptQueue.front();
			ScriptQueue.erase(ScriptQueue.begin());

			if (!Script.empty())
				executeScript(Script);
		}

		return OriginalVF(A1, A2, A3);
	}

	void HookJob(const std::string& Name) {
		uintptr_t Job = scheduler::getJobByName(Name);
		if (!Job) return;

		void** VTable = new void* [25]();
		memcpy(VTable, *(void**)Job, sizeof(uintptr_t) * 25);

		OriginalVF = (JobOriginalVF)VTable[2];
		VTable[2] = Cycle;

		*(void**)Job = VTable;
	}

	void initialize()
	{
		auto scriptContext = scheduler::getScriptContext();

		uintptr_t x = 0;

		auto encryptedState = functions::GetGlobalState(scriptContext + offsets::getGlobalOffset, &x, &x);
		auto decryptedState = functions::DecryptState(encryptedState + offsets::decryptStateOffset);

		state = decryptedState;

		functions::setIdentity(state, 8, maxCaps);
	}

	void addScript(std::string script)
	{
		ScriptQueue.push_back(script);
	}
}
