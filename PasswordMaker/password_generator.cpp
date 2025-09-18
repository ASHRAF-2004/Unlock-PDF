#include <bits/stdc++.h>
using namespace std;

struct Args {
  int minLen = 10;
  int maxLen = 10;
  bool includeUpper = true;
  bool includeLower = true;
  bool includeDigits = true;
  bool includeSpecial = false;
  bool userOnly = false;
  string userChars = "";
};

long double safePowLD(size_t base, int exp) {
  long double r = 1.0L;
  for (int i = 0; i < exp; ++i) r *= static_cast<long double>(base);
  return r;
}

Args parseArgs(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    string k = argv[i];
    auto next = [&](int i)->string {
      if (i + 1 >= argc) throw runtime_error("Missing value for " + k);
      return string(argv[i + 1]);
    };
    if (k == "--min")        a.minLen = stoi(next(i++));
    else if (k == "--max")   a.maxLen = stoi(next(i++));
    else if (k == "--upper") a.includeUpper = stoi(next(i++)) != 0;
    else if (k == "--lower") a.includeLower = stoi(next(i++)) != 0;
    else if (k == "--digits")a.includeDigits = stoi(next(i++)) != 0;
    else if (k == "--special")a.includeSpecial = stoi(next(i++)) != 0;
    else if (k == "--user-only") a.userOnly = stoi(next(i++)) != 0;
    else if (k == "--user")  a.userChars = next(i++);
    else if (k == "--help" || k == "-h") {
      cout <<
      "Usage:\n"
      "  --min N            minimum length\n"
      "  --max N            maximum length\n"
      "  --upper 0|1        include uppercase A-Z\n"
      "  --lower 0|1        include lowercase a-z\n"
      "  --digits 0|1       include digits 0-9\n"
      "  --special 0|1      include specials !@#$.../~\n"
      "  --user-only 0|1    use only user-defined characters\n"
      "  --user \"chars\"     user-defined chars (used if --user-only=1)\n";
      exit(0);
    }
  }
  if (a.minLen < 1 || a.maxLen < a.minLen) throw runtime_error("Invalid min/max length.");
  return a;
}

string buildCharset(const Args& a) {
  string chars;
  const string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const string L = "abcdefghijklmnopqrstuvwxyz";
  const string D = "0123456789";
  const string S = "!@#$%^&*()_+={}[]|:;<>,.?/~";

  if (a.userOnly) {
    if (a.userChars.empty())
      throw runtime_error("--user-only=1 requires non-empty --user \"...\"");
    chars = a.userChars;
  } else {
    if (a.includeUpper)  chars += U;
    if (a.includeLower)  chars += L;
    if (a.includeDigits) chars += D;
    if (a.includeSpecial)chars += S;
  }

  // Deduplicate characters to avoid repeated symbols
  sort(chars.begin(), chars.end());
  chars.erase(unique(chars.begin(), chars.end()), chars.end());

  if (chars.empty()) throw runtime_error("Character set is empty.");
  return chars;
}

// Iterative base-N counter approach: writes directly to file (no huge memory).
void generateLength(ofstream& out, const string& chars, int length, bool showProgress) {
  const size_t N = chars.size();
  if (length <= 0) return;

  // vector of indexes representing current word in base-N
  vector<size_t> idx(length, 0);
  string word(length, '\0');

  // total combinations for this length: N^length (may be enormous)
  // We won't loop based on that number; we stop when we've overflowed the counter.
  uint64_t counter = 0;
  const uint64_t PRINT_EVERY = 1'000'000ULL;

  while (true) {
    for (int i = 0; i < length; ++i) word[i] = chars[idx[i]];
    out << word << '\n';

    if (showProgress && (++counter % PRINT_EVERY == 0)) {
      cerr << "[len " << length << "] generated: " << counter << "\r";
    }

    // increment base-N counter
    int pos = length - 1;
    while (pos >= 0) {
      if (++idx[pos] < N) break;
      idx[pos] = 0;
      --pos;
    }
    if (pos < 0) break; // overflowed: finished all combos
  }
  if (showProgress) cerr << string(60, ' ') << "\r";
}

int main(int argc, char** argv) {
  ios::sync_with_stdio(false);
  cin.tie(nullptr);

  try {
    Args a = parseArgs(argc, argv);
    string charset = buildCharset(a);

    // Rough total count (may overflow normal integers, so use long double for info only)
    long double total = 0.0L;
    for (int len = a.minLen; len <= a.maxLen; ++len) {
      total += safePowLD(charset.size(), len);
    }

    cout << "Charset size: " << charset.size() << "\n";
    cout << "Lengths: [" << a.minLen << ", " << a.maxLen << "]\n";
    cout << fixed << setprecision(0);
    cout << "Estimated total combos (approx): " << total << "\n";
    cout.unsetf(ios::floatfield);

    ofstream out("passwordlist.txt");
    if (!out) throw runtime_error("Failed to open passwordlist.txt for writing.");

    // NOTE: This can run for an astronomically long time for big ranges/charsets.
    // Consider splitting work or narrowing ranges.
    bool showProgress = true;
    for (int len = a.minLen; len <= a.maxLen; ++len) {
      generateLength(out, charset, len, showProgress);
    }

    out.close();
    cout << "Password-list generated successfully -> passwordlist.txt\n";
    return 0;

  } catch (const exception& e) {
    cerr << "Error: " << e.what() << "\n";
    return 1;
  }
}
