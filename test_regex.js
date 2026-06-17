const patterns = [
    /sk-[a-zA-Z0-9]{10,}/g,                        // OpenAI style keys
    /api[_-]?key\s*=\s*(["'][^"']+["'])/gi,          // API keys
    /password\s*=\s*(["'][^"']+["'])/gi,             // passwords
    /token\s*=\s*(["'][^"']+["'])/gi,                // tokens
    /secret\s*=\s*(["']?[^"']+["']?)/gi,               // secrets
    /AKIA[0-9A-Z]{16}/g,                          // AWS keys
    /ghp_[A-Za-z0-9]{20,}/g                       // GitHub tokens
];

const text = 'const password ="sk-a1233dxkd"';
let results = [];
for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
        results.push(match[1] ? match[1] : match[0]);
    }
}
console.log(results);
 