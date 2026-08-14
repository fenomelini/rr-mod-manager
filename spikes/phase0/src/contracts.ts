import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";

export function compileContract(schema: object): ValidateFunction {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addFormat("uri", {
    type: "string",
    validate(value: string): boolean {
      try {
        const parsed = new URL(value);
        return parsed.protocol === "https:" || parsed.protocol === "http:";
      } catch {
        return false;
      }
    },
  });
  return ajv.compile(schema);
}

export function formatContractErrors(validate: ValidateFunction): string[] {
  return (validate.errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message ?? "invalid"}`);
}
