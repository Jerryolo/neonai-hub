import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

const PORT = Number(process.env.PORT || 8787);
const ROOT = process.cwd();
const MODEL = "gpt-5.6-sol";

async function loadConfig(){
  const candidates = [
    process.env.OPENAI_API_KEY,
    process.env.OPENAI_KEY
  ];

  if(process.env.OPENAI_CONFIG_PATH){
    try{
      const config = JSON.parse(await readFile(process.env.OPENAI_CONFIG_PATH, "utf8"));
      candidates.push(config.openaiApiKey, config.OPENAI_API_KEY);
    }catch(error){
      console.warn("Could not read OPENAI_CONFIG_PATH:", error.message);
    }
  }

  return {
    apiKey:candidates.find(value => typeof value === "string" && value.trim())?.trim() || ""
  };
}

function sendJson(response, status, payload){
  response.writeHead(status, {"Content-Type":"application/json"});
  response.end(JSON.stringify(payload));
}

async function readJson(request){
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

async function askOpenAI(question, apiKey){
  const response = await fetch("https://api.openai.com/v1/responses", {
    method:"POST",
    headers:{
      "Authorization":`Bearer ${apiKey}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      model:MODEL,
      input:[{
        role:"user",
        content:[{type:"input_text", text:question}]
      }]
    })
  });

  const payload = await response.json().catch(() => ({}));
  if(!response.ok){
    throw new Error(payload.error?.message || `OpenAI returned HTTP ${response.status}`);
  }

  return payload.output_text
    || payload.output?.flatMap(item => item.content || [])
      .map(part => part.text || "")
      .join("\n")
      .trim()
    || "";
}

async function serveStatic(request, response){
  const url = new URL(request.url, `http://${request.headers.host}`);
  const pathname = url.pathname === "/" ? "/pos-live-demo.html" : url.pathname;
  const filePath = normalize(join(ROOT, pathname));

  if(!filePath.startsWith(ROOT)){
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  try{
    const file = await readFile(filePath);
    const type = extname(filePath) === ".js" ? "text/javascript"
      : extname(filePath) === ".html" ? "text/html"
      : "application/octet-stream";
    response.writeHead(200, {"Content-Type":type});
    response.end(file);
  }catch(error){
    response.writeHead(404);
    response.end("Not found");
  }
}

createServer(async (request, response) => {
  const config = await loadConfig();

  try{
    if(request.method === "GET" && request.url === "/api/openai-status"){
      sendJson(response, 200, {configured:Boolean(config.apiKey), model:MODEL});
      return;
    }

    if(request.method === "POST" && request.url === "/api/ask"){
      if(!config.apiKey){
        sendJson(response, 503, {error:"OpenAI API key is not configured."});
        return;
      }

      const {question} = await readJson(request);
      if(!question || typeof question !== "string"){
        sendJson(response, 400, {error:"A question string is required."});
        return;
      }

      const answer = await askOpenAI(question, config.apiKey);
      sendJson(response, 200, {model:MODEL, answer});
      return;
    }
  }catch(error){
    sendJson(response, 500, {error:error.message});
    return;
  }

  if(request.method === "GET"){
    await serveStatic(request, response);
    return;
  }

  response.writeHead(405);
  response.end("Method not allowed");
}).listen(PORT, () => {
  console.log(`Proof-of-Silence demo running at http://localhost:${PORT}`);
  console.log("Set OPENAI_API_KEY or OPENAI_CONFIG_PATH to enable GPT-5.6 API mode.");
});
