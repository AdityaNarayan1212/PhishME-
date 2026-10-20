const fs=require('fs');
const lines=fs.readFileSync('./script.js','utf8').split('\n');
console.log('L92 RAW:', JSON.stringify(lines[91].slice(0,160)));
console.log('L142 RAW:', JSON.stringify(lines[141].slice(0,120)));