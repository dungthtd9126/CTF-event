#include "openfhe.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <random>
#include <ctime>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iomanip>
#include <fstream>

using namespace lbcrypto;
const uint32_t TARGET_RING_DIM = 16;
const uint32_t AUX_RING_DIM = 8;
const uint32_t BATCH_SIZE = 16;
const uint32_t AUX_NUM_SAMPLES = 2;
const int64_t  P_MOD = 65537;      // Plaintext modulus
const int64_t  T_MIN = (1LL << 59);
const int64_t  T_MAX = (1LL << 60);
const double   ERROR_SIGMA = 2.0; 
const int      PORT = 1337;

CryptoContext<DCRTPoly> cc;
DCRTPoly T; 
DCRTPoly S;
std::vector<DCRTPoly> B_samples;
std::vector<DCRTPoly> S_samples;
std::vector<DCRTPoly> K_samples;
std::string encrypted_flag_1;
std::string encrypted_flag_2;
std::mt19937_64 rng;

size_t GetRingDim() {
    return cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
}

// --- Helper: Generate T ---
template <typename ParamsPtr>
DCRTPoly GenLargeSecretPoly(const ParamsPtr& params, size_t ring_dim) {
    std::uniform_int_distribution<int64_t> dist(T_MIN, T_MAX);
    std::vector<int64_t> coeffs(ring_dim);
    for (auto& coeff : coeffs) {
        coeff = dist(rng);
    }
    std::sort(coeffs.begin(), coeffs.end());

    DCRTPoly poly(params, COEFFICIENT, true);
    for (size_t i = 0; i < poly.GetNumOfElements(); i++) {
        auto tower_params = params->GetParams()[i];
        DCRTPoly::PolyType v(tower_params, COEFFICIENT, true);
        auto modulus = tower_params->GetModulus().ConvertToInt();
        std::vector<int64_t> reduced_coeffs(ring_dim);
        for (size_t j = 0; j < ring_dim; j++) {
            reduced_coeffs[j] = coeffs[j] % modulus;
        }
        v = reduced_coeffs;
        poly.SetElementAtIndex(i, v);
    }
    poly.SetFormat(EVALUATION);
    return poly;
}

std::vector<int64_t> GetPolyCoefficients(DCRTPoly poly) {
    DCRTPoly coeff_poly = poly;
    coeff_poly.SetFormat(COEFFICIENT);
    auto values = coeff_poly.GetElementAtIndex(0).GetValues();

    std::vector<int64_t> coeffs(values.GetLength());
    for (size_t i = 0; i < values.GetLength(); i++) {
        coeffs[i] = values[i].ConvertToInt();
    }
    return coeffs;
}

std::vector<int64_t> GetPolyCoefficientsSigned(DCRTPoly poly) {
    DCRTPoly coeff_poly = poly;
    coeff_poly.SetFormat(COEFFICIENT);
    auto values = coeff_poly.GetElementAtIndex(0).GetValues();
    auto q = coeff_poly.GetElementAtIndex(0).GetModulus();
    auto qHalf = q / 2;

    std::vector<int64_t> coeffs(values.GetLength());
    for (size_t i = 0; i < values.GetLength(); i++) {
        auto val = values[i];
        if (val > qHalf) {
            coeffs[i] = -1 * (int64_t)(q - val).ConvertToInt();
        } else {
            coeffs[i] = (int64_t)val.ConvertToInt();
        }
    }
    return coeffs;
}

std::string HexEncode(const std::string& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char ch : data) {
        oss << std::setw(2) << static_cast<int>(ch);
    }
    return oss.str();
}

std::string GenerateRandomHex(size_t byte_len) {
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 255);

    std::string out;
    out.reserve(byte_len * 2);
    for (size_t i = 0; i < byte_len; i++) {
        unsigned char byte = static_cast<unsigned char>(dist(rng));
        out.push_back(HEX_DIGITS[byte >> 4]);
        out.push_back(HEX_DIGITS[byte & 0x0f]);
    }
    return out;
}

std::string ReadFlag(const std::string& path) {
    std::ifstream file(path);
    std::string flag;
    std::getline(file, flag);
    while (!flag.empty() && (flag.back() == '\n' || flag.back() == '\r')) {
        flag.pop_back();
    }
    if (flag.rfind("HCMUS-CTF{", 0) == 0 && flag.back() == '}') {
        return flag.substr(10, flag.length() - 11);
    }
    return flag;
}

void InitEncryptedFlag() {
    const std::vector<int64_t> t_coeffs = GetPolyCoefficientsSigned(T);
    std::vector<unsigned char> key_bytes;
    key_bytes.reserve(t_coeffs.size() * 8);
    for (int64_t coeff : t_coeffs) {
        for (int j = 0; j < 8; j++) {
            key_bytes.push_back(static_cast<unsigned char>((coeff >> (j * 8)) & 0xff));
        }
    }
    // TODO DEBUG
    // std::cout << "key_bytes [";
    // for (size_t i = 0; i < key_bytes.size(); i++) {
    //     std::cout << (int)key_bytes[i] << (i == key_bytes.size() - 1 ? "" : ", ");
    // }
    // std::cout << "]" << std::endl;

    auto encrypt_body = [&](const std::string& body) {
        std::string flag_body = body;
        size_t target_len = std::max({(size_t)32, body.length()});

        if (flag_body.length() < target_len) {
            size_t needed = target_len - flag_body.length();
            std::string padding = GenerateRandomHex((needed + 1) / 2);
            flag_body += padding.substr(0, needed);
        } else if (flag_body.length() > target_len) {
            flag_body = flag_body.substr(0, target_len);
        }

        std::string masked_body;
        masked_body.reserve(flag_body.size());
        for (size_t i = 0; i < flag_body.size(); i++) {
            unsigned char mask = key_bytes[i % key_bytes.size()];
            masked_body.push_back(static_cast<char>(static_cast<unsigned char>(flag_body[i]) ^ mask));
        }
        return HexEncode(masked_body);
    };

    encrypted_flag_1 = encrypt_body(ReadFlag("deploy/flag1.txt"));
    encrypted_flag_2 = encrypt_body(ReadFlag("deploy/flag2.txt"));
}

// --- Helper: Serialize Polynomial to String ---
std::string PolyToString(DCRTPoly p) {
    p.SetFormat(COEFFICIENT);
    // Use CRT interpolation to get the coefficients mod q
    Poly p_reconstructed = p.CRTInterpolate();
    auto values = p_reconstructed.GetValues();
    
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < values.GetLength(); i++) {
        ss << values[i].ToString() << (i == (values.GetLength() - 1) ? "" : ", ");
    }
    ss << "]";
    return ss.str();
}

std::string PolyToStringModQ(DCRTPoly p, const BigInteger& q) {
    auto coeffs = GetPolyCoefficients(p);
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < coeffs.size(); i++) {
        BigInteger val;
        if (coeffs[i] < 0) {
            val = q - BigInteger(-coeffs[i]);
        } else {
            val = BigInteger(coeffs[i]);
        }
        ss << val.ToString() << (i == (coeffs.size() - 1) ? "" : ", ");
    }
    ss << "]";
    return ss.str();
}



void init_challenge() {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(P_MOD);
    parameters.SetRingDim(TARGET_RING_DIM);
    parameters.SetBatchSize(BATCH_SIZE);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(2);
    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly::TugType tug;
    DCRTPoly::DggType dgg(ERROR_SIGMA);

    CCParams<CryptoContextBFVRNS> auxParameters;
    auxParameters.SetPlaintextModulus(P_MOD);
    auxParameters.SetRingDim(AUX_RING_DIM);
    auxParameters.SetBatchSize(AUX_RING_DIM);
    auxParameters.SetSecurityLevel(HEStd_NotSet);
    auxParameters.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> aux_cc = GenCryptoContext(auxParameters);
    auto auxParams = aux_cc->GetCryptoParameters()->GetElementParams();

    T = GenLargeSecretPoly(auxParams, AUX_RING_DIM);
    InitEncryptedFlag();

    B_samples.clear();
    K_samples.clear();
    S_samples.clear();
    B_samples.reserve(AUX_NUM_SAMPLES);
    K_samples.reserve(AUX_NUM_SAMPLES);
    S_samples.reserve(AUX_NUM_SAMPLES);
    for (uint32_t i = 0; i < AUX_NUM_SAMPLES; i++) {
        DCRTPoly B_i(tug, auxParams, EVALUATION);
        DCRTPoly K_i(dgg, auxParams, EVALUATION);
        B_samples.push_back(B_i);
        K_samples.push_back(K_i);
        S_samples.push_back(B_i * T + K_i);
    }

    std::vector<int64_t> s_combined;
    for (auto& s_samp : S_samples) {
        auto coeffs = GetPolyCoefficients(s_samp);
        s_combined.insert(s_combined.end(), coeffs.begin(), coeffs.end());
    }
    params = cc->GetCryptoParameters()->GetElementParams();
    S = DCRTPoly(params, COEFFICIENT, true);
    S = s_combined;
    S.SetFormat(EVALUATION);

    // TODO DEBUG
    // std::vector<int64_t> k_combined;
    // for (auto& k_samp : K_samples) {
    //     auto coeffs = GetPolyCoefficients(k_samp);
    //     k_combined.insert(k_combined.end(), coeffs.begin(), coeffs.end());
    // }
    // DCRTPoly K_poly(params, COEFFICIENT, true);
    // K_poly = k_combined;

    // std::cout << "S " << PolyToString(S) << std::endl;
    // std::cout << "K " << PolyToString(K_poly) << std::endl;
    // std::cout << "T " << PolyToString(T) << std::endl;
}

void handle_client(int client_fd) {
    std::string banner = "=== Funny Helicopter Morphology - version Beef Feast Victory!! ===\n";
    send(client_fd, banner.c_str(), banner.length(), 0);

    bool used_hint = false;
    bool used_params = false;

    char buffer[4096];
    while (true) {
        memset(buffer, 0, 4096);
        int bytes = recv(client_fd, buffer, 4096, 0);
        if (bytes <= 0) break;

        std::string cmd(buffer, bytes);
        std::stringstream ss(cmd);
        std::string action;
        ss >> action;

        if (action == "PARAMS") {
            auto params = cc->GetCryptoParameters()->GetElementParams();
            std::string res = "n: " + std::to_string(GetRingDim()) + "\n" +
                             "q: " + params->GetModulus().ToString() + "\n" +
                             "q0: " + params->GetParams()[0]->GetModulus().ToString() + "\n" +
                             "Encrypted flag: " + (used_hint ? encrypted_flag_1 : encrypted_flag_2) + "\n";
            used_params = true;
            send(client_fd, res.c_str(), res.length(), 0);
        }
        else if (action == "EVALSUM") {
            if (used_params) {
                continue;
            }
            used_hint = true;
            std::stringstream res;
            auto main_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus();
            for (size_t i = 0; i < B_samples.size(); i++) {
                res << "B" << i << ": " << PolyToString(B_samples[i]) << "\n";
                res << "S" << i << ": " << PolyToStringModQ(S_samples[i], main_q) << "\n";
            }
           
            std::string out = res.str();
            send(client_fd, out.c_str(), out.length(), 0);
        }
        else if (action == "CHALLENGE") {
            int num_samples;
            if (!(ss >> num_samples)) {
                std::string err = "ERROR: Provide number of samples (1-10).\n";
                send(client_fd, err.c_str(), err.length(), 0);
                continue;
            }
            if (num_samples < 1 || num_samples > 10) {
                std::string err = "ERROR: Number of samples must be between 1 and 10.\n";
                send(client_fd, err.c_str(), err.length(), 0);
                continue;
            }

            std::vector<int64_t> v_vals;
            int64_t val;
            while (ss >> val) v_vals.push_back(val);
            
            if (v_vals.empty()) {
                std::string err = "ERROR: Provide at least one message value.\n";
                send(client_fd, err.c_str(), err.length(), 0);
                continue;
            }

            try {
                std::stringstream ss_res;
                Plaintext pt = cc->MakePackedPlaintext(v_vals);
                
                const auto& elementParams = cc->GetCryptoParameters()->GetElementParams();

                pt->Encode();
                DCRTPoly m_poly = pt->GetElement<DCRTPoly>();
                m_poly.SetFormat(EVALUATION);

                DCRTPoly::TugType tgg;  
                DCRTPoly::DggType dgg(ERROR_SIGMA);
                BigInteger r(std::uniform_int_distribution<uint64_t>(2, elementParams->GetParams()[0]->GetModulus().ConvertToInt() - 1)(rng));
                ss_res << "r: " << r << "\n";
                for (uint32_t i = 0; i < (uint32_t)num_samples; i++) {
                    DCRTPoly a(tgg, elementParams, EVALUATION);
                    DCRTPoly e = DCRTPoly(dgg, elementParams, EVALUATION);
                    
                    // TODO DEBUG
                    // std::cout << "e[" << i << "] " << PolyToString(e) << std::endl;
                    
                    DCRTPoly c0 = a * S + e * r + m_poly;
                    
                    a.SetFormat(COEFFICIENT);
                    c0.SetFormat(COEFFICIENT);
                    
                    ss_res << "SAMPLE " << i << "\n";
                    ss_res << "C1: " << PolyToString(a) << "\n";
                    ss_res << "C0: " << PolyToString(c0) << "\n";
                }

                // free hints!!
                std::vector<int64_t> e_coeffs;
                for (auto& k_samp : K_samples) {
                    auto coeffs = GetPolyCoefficientsSigned(k_samp);
                    e_coeffs.insert(e_coeffs.end(), coeffs.begin(), coeffs.end());
                }
                for (size_t i = 0; i < std::min<size_t>(2, e_coeffs.size()); i++) {
                    ss_res << "E[" << i << "]: " << e_coeffs[i] << "\n";
                }

                std::string res = ss_res.str();
                send(client_fd, res.c_str(), res.length(), 0);
            } catch (const std::exception& e) {
                std::string err = "ERROR: " + std::string(e.what()) + "\n";
                send(client_fd, err.c_str(), err.length(), 0);
            }

            break;
        }
        else if (action == "EXIT") break;
    }
    close(client_fd);
}

int main() {
    rng.seed(std::random_device{}());

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return 1;
    listen(server_fd, 5);
    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            rng.seed(std::random_device{}());
            init_challenge();
            handle_client(client_fd);
        }
    }
    return 0;
}
