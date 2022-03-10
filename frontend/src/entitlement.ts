/**
 * This file was auto-generated by openapi-typescript.
 * Do not make direct changes to the file.
 */

export interface paths {
  "/": {
    get: operations["read_semver__get"];
  };
  "/healthz": {
    get: operations["read_liveness_healthz_get"];
  };
  "/v1/entity/attribute": {
    get: operations["read_relationship_v1_entity_attribute_get"];
  };
  "/v1/entity/claimsobject": {
    get: operations["read_relationship_v1_entity_claimsobject_get"];
  };
  "/v1/entity/{entityId}/attribute": {
    get: operations["read_entity_attribute_relationship_v1_entity__entityId__attribute_get"];
    put: operations["create_entity_attribute_relationship_v1_entity__entityId__attribute_put"];
  };
  "/v1/entity/{entityId}/claimsobject": {
    get: operations["read_entity_attribute_relationship_v1_entity__entityId__claimsobject_get"];
  };
  "/v1/attribute/{attributeURI}/entity/": {
    put: operations["create_attribute_entity_relationship_v1_attribute__attributeURI__entity__put"];
  };
  "/v1/entity/{entityId}/attribute/{attributeURI}": {
    delete: operations["delete_attribute_entity_relationship_v1_entity__entityId__attribute__attributeURI__delete"];
  };
}

export interface components {
  schemas: {
    ClaimsObject: {
      attribute: string;
    };
    EntityAttributeRelationship: Record<string, string[]>;
    HTTPValidationError: {
      detail?: components["schemas"]["ValidationError"][];
    };
    /** An enumeration. */
    ProbeType: "liveness" | "readiness";
    ValidationError: {
      loc: string[];
      msg: string;
      type: string;
    };
  };
}

export interface operations {
  read_semver__get: {
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": unknown;
        };
      };
    };
  };
  read_liveness_healthz_get: {
    parameters: {
      query: {
        probe?: components["schemas"]["ProbeType"];
      };
    };
    responses: {
      /** Successful Response */
      204: never;
      /** Validation Error */
      422: {
        content: {
          "application/json": components["schemas"]["HTTPValidationError"];
        };
      };
    };
  };
  read_relationship_v1_entity_attribute_get: {
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": components["schemas"]["EntityAttributeRelationship"][];
        };
      };
    };
  };
  read_relationship_v1_entity_claimsobject_get: {
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": components["schemas"]["ClaimsObject"][];
        };
      };
    };
  };
  read_entity_attribute_relationship_v1_entity__entityId__attribute_get: {
    parameters: {
      path: {
        entityId: string;
      };
    };
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": unknown;
        };
      };
      /** Validation Error */
      422: {
        content: {
          "application/json": components["schemas"]["HTTPValidationError"];
        };
      };
    };
  };
  create_entity_attribute_relationship_v1_entity__entityId__attribute_put: {
    parameters: {
      path: {
        entityId: string;
      };
    };
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": unknown;
        };
      };
      /** Validation Error */
      422: {
        content: {
          "application/json": components["schemas"]["HTTPValidationError"];
        };
      };
    };
    requestBody: {
      content: {
        "application/json": string[];
      };
    };
  };
  read_entity_attribute_relationship_v1_entity__entityId__claimsobject_get: {
    parameters: {
      path: {
        entityId: string;
      };
    };
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": unknown;
        };
      };
      /** Validation Error */
      422: {
        content: {
          "application/json": components["schemas"]["HTTPValidationError"];
        };
      };
    };
  };
  create_attribute_entity_relationship_v1_attribute__attributeURI__entity__put: {
    parameters: {
      path: {
        attributeURI: string;
      };
    };
    responses: {
      /** Successful Response */
      200: {
        content: {
          "application/json": unknown;
        };
      };
      /** Validation Error */
      422: {
        content: {
          "application/json": components["schemas"]["HTTPValidationError"];
        };
      };
    };
    requestBody: {
      content: {
        "application/json": string[];
      };
    };
  };
  delete_attribute_entity_relationship_v1_entity__entityId__attribute__attributeURI__delete: {
    parameters: {
      path: {
        entityId: string;
        attributeURI: string;
      };
    };
    responses: {
      /** Successful Response */
      204: never;
      /** Validation Error */
      422: {
        content: {
          "application/json": components["schemas"]["HTTPValidationError"];
        };
      };
    };
  };
}

export interface external { }