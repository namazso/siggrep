//	siggrep - A grep-like utility for testing for binary patterns in a file
//	Copyright (C) 2021  namazso
//	
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, either version 3 of the License, or
//	(at your option) any later version.
//	
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU General Public License for more details.
//	
//	You should have received a copy of the GNU General Public License
//	along with this program.  If not, see <https://www.gnu.org/licenses/>.
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>

template <typename Char>
uint8_t unhex(Char ch)
{
  if (ch >= 0x80 || ch <= 0)
    return 0xFF;

  const auto c = (char)ch;

#define TEST_RANGE(c, a, b, offset) if (uint8_t(c) >= uint8_t(a) && uint8_t(c) <= uint8_t(b))\
  return uint8_t(c) - uint8_t(a) + (offset)

  TEST_RANGE(c, '0', '9', 0x0);
  TEST_RANGE(c, 'a', 'f', 0xa);
  TEST_RANGE(c, 'A', 'F', 0xA);

#undef TEST_RANGE

  return 0xFF;
};

using Signature = std::vector<std::pair<uint8_t, bool>>;

struct Arguments
{
  std::wstring file;
  std::vector<Signature> sigs;
};

Signature parse_sig(const wchar_t* str)
{
  Signature sig;

  enum class State
  {
    AfterSpace,
    AfterFirst,
    AfterSecond,
    AfterWildcard,
  } state = State::AfterSpace;

  uint8_t nibble{};

  while (const auto c = *str++)
  {
    switch (state)
    {
    case State::AfterSpace:
    {
      nibble = unhex(c);

      if (isspace(c))
        (void)0;
      else if (c == L'?')
      {
        sig.emplace_back(0, false);
        state = State::AfterWildcard;
      }
      else if (nibble != 0xFF)
      {
        state = State::AfterFirst;
      }
      else
        return {};
      break;
    }
    case State::AfterFirst:
    {
      const auto second = unhex(c);
      if (second != 0xFF)
      {
        sig.emplace_back((nibble << 4) | second, true);
        state = State::AfterSecond;
      }
      else
        return {};
      break;
    }
    case State::AfterSecond:
    {
      if (isspace(c))
        state = State::AfterSpace;
      else
        return {};
      break;
    }
    case State::AfterWildcard:
    {
      if (isspace(c))
        state = State::AfterSpace;
      else if (c == L'?')
        (void)0;
      else
        return {};
      break;
    }
    }
  }

  if (state == State::AfterFirst)
    return {};

  return sig;
}

bool parse_args(Arguments& args, int argc, wchar_t** argv)
{
  args.file.clear();
  args.sigs.clear();

  enum class State
  {
    Type,
    ValuePattern,
    ValueNarrow,
    ValueWide,
    ValueWideBE,
    FileOnly,
    Done
  } state = State::Type;

  for (int i = 1; i < argc; ++i)
  {
    const auto arg = argv[i];
    if (state == State::Type)
    {
      if (0 == wcscmp(arg, L"--pattern"))
        state = State::ValuePattern;
      else if (0 == wcscmp(arg, L"--narrow"))
        state = State::ValueNarrow;
      else if (0 == wcscmp(arg, L"--wide"))
        state = State::ValueWide;
      else if (0 == wcscmp(arg, L"--widebe"))
        state = State::ValueWideBE;
      else if (0 == wcscmp(arg, L"--"))
        state = State::FileOnly;
      else
      {
        args.file = arg;
        state = State::Done;
      }
    }
    else if (state == State::FileOnly)
    {
      args.file = arg;
      state = State::Done;
    }
    else if (state == State::ValuePattern)
    {
      auto sig = parse_sig(arg);
      if (sig.empty())
        return false;
      args.sigs.emplace_back(std::move(sig));
      state = State::Type;
    }
    else if (state == State::ValueNarrow)
    {
      Signature sig;
      for (auto c : std::wstring{ arg })
      {
        const auto ushort = (uint16_t)c;
        if (ushort > 0xFF)
          return false;
        sig.emplace_back((uint8_t)ushort, true);
      }
      args.sigs.emplace_back(std::move(sig));
      state = State::Type;
    }
    else if (state == State::ValueWide)
    {
      Signature sig;
      for (auto c : std::wstring{ arg })
      {
        const auto ushort = (uint16_t)c;
        sig.emplace_back((uint8_t)ushort, true);
        sig.emplace_back((uint8_t)(ushort >> 8), true);
      }
      args.sigs.emplace_back(std::move(sig));
      state = State::Type;
    }
    else if (state == State::ValueWideBE)
    {
      Signature sig;
      for (auto c : std::wstring{ arg })
      {
        const auto ushort = (uint16_t)c;
        sig.emplace_back((uint8_t)(ushort >> 8), true);
        sig.emplace_back((uint8_t)ushort, true);
      }
      args.sigs.emplace_back(std::move(sig));
      state = State::Type;
    }
    else
      return false;
  }

  if (args.sigs.empty())
    return false;
  if (state != State::Done)
    return false;

  return true;
}

bool read_all(const wchar_t* path, std::vector<uint8_t>& data)
{
  data.clear();
  std::ifstream is(path, std::ios::binary);
  if (!is.good() || !is.is_open())
    return false;
  is.seekg(0, std::ifstream::end);
  data.resize((size_t)is.tellg());
  is.seekg(0, std::ifstream::beg);
  is.read(reinterpret_cast<char*>(data.data()), (std::streamsize)data.size());
  if (!is.good() || !is.is_open())
    return false;
  return true;
}

template <typename It>
int count_sig(It begin, It end, Signature& sig)
{
  int count = 0;

  while (true)
  {
    begin = std::search(begin, end, sig.begin(), sig.end(),
      [](uint8_t curr, std::pair<uint8_t, bool> curr_pattern)
      {
        return (!curr_pattern.second) || curr == curr_pattern.first;
      });
    if (begin == end)
      return count;
    ++count;
    ++begin;
    if (begin == end)
      return count;
  }
}

int wmain(int argc, wchar_t** argv)
{
  Arguments args;
  if(!parse_args(args, argc, argv))
  {
    fwprintf(stderr, LR"(Usage: %s [--(pattern|narrow|wide|widebe) <value>]+ [--] <file>
Options:
  --pattern <pattern>     IDA style pattern, like "12 34 ? 78"
  --narrow <string>       narrow / ascii string
  --wide <string>         wide / ucs2 little endian string
  --widebe <string>       wide / ucs2 big endian string
Output:
  Comma separated values of count of each signature found
)", argv[0]);
    return 1;
  }

  std::vector<uint8_t> file;
  if (!read_all(args.file.c_str(), file))
  {
    fwprintf(stderr, L"Failed opening or reading file %s\n", args.file.c_str());
    return 2;
  }

  const auto sig_count = args.sigs.size();
  for (size_t i = 0; i < sig_count; ++i)
  {
    const auto count = count_sig(file.begin(), file.end(), args.sigs[i]);
    if (i == sig_count - 1)
      printf("%d\n", count);
    else
      printf("%d,", count);
  }
  return 0;
}

