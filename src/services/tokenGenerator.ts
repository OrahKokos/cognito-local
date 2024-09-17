import { PreTokenGenerationTriggerEvent } from "aws-lambda/trigger/cognito-user-pool-trigger/pre-token-generation";
import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import PrivateKey from "../keys/cognitoLocal.private.json";
import { AppClient } from "./appClient";
import { Clock } from "./clock";
import { Context } from "./context";
import { Triggers } from "./triggers";
import {
  attributesToRecord,
  attributeValue,
  customAttributes,
  User,
} from "./userPoolService";
import { ClaimsAndScopeOverrideDetails } from "aws-lambda/trigger/cognito-user-pool-trigger/pre-token-generation-v2";

type ValidityUnit =
  | "milliseconds"
  | "seconds"
  | "minutes"
  | "hours"
  | "days"
  | string;

enum ValidityUnitEnum {
  MILLISECONDS = "milliseconds",
  SECONDS = "seconds",
  MINUTES = "minutes",
  HOURS = "hours",
  DAYS = "days",
}

export interface TokenConfig {
  IssuerDomain?: string;
}

export interface Token {
  client_id: string;
  iss: string;
  sub: string;
  token_use: string;
  username: string;
  event_id: string;
  scope: string;
  auth_time: Date;
  jti: string;
}

const RESERVED_CLAIMS = [
  "acr",
  "amr",
  "aud",
  "at_hash",
  "auth_time",
  "azp",
  "cognito:username",
  "exp",
  "iat",
  "identities",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "origin_jti",
  "sub",
  "token_use",
];

type RawToken = Record<
  string,
  string | number | boolean | undefined | readonly string[]
>;

type Overrides =
  | ClaimsAndScopeOverrideDetails["accessTokenGeneration"]
  | PreTokenGenerationTriggerEvent["response"]["claimsOverrideDetails"]
  | ClaimsAndScopeOverrideDetails["idTokenGeneration"];

const applyTokenOverrides = (
  token: RawToken,
  overrides: Overrides
): RawToken => {
  const claimsToSuppress = (overrides?.claimsToSuppress ?? []).filter(
    (claim) => !RESERVED_CLAIMS.includes(claim)
  );

  const claimsToOverride = Object.entries(
    overrides?.claimsToAddOrOverride ?? []
  ).filter(([claim]) => !RESERVED_CLAIMS.includes(claim));

  return Object.fromEntries(
    [...Object.entries(token), ...claimsToOverride].filter(
      ([claim]) => !claimsToSuppress.includes(claim)
    )
  );
};

export interface Tokens {
  readonly AccessToken: string;
  readonly IdToken: string;
  readonly RefreshToken: string;
}

export interface TokenGenerator {
  generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens"
  ): Promise<Tokens>;
}

const isValidUnit = (unit?: ValidityUnitEnum) =>
  unit ? Object.values(ValidityUnitEnum).includes(unit) : false;

const formatExpiration = (
  duration: string | number | undefined,
  unit: ValidityUnit,
  fallback: string
): string | number => {
  if (duration === undefined || !isValidUnit(unit as ValidityUnitEnum)) {
    return fallback;
  }
  if (unit === ValidityUnitEnum.SECONDS) {
    if (typeof duration === "string") return parseInt(duration);
    return duration;
  }
  if (unit === ValidityUnitEnum.MILLISECONDS) {
    if (typeof duration === "number") return String(duration);
    return duration;
  }
  return `${duration}${unit}`;
};

export class JwtTokenGenerator implements TokenGenerator {
  private readonly clock: Clock;
  private readonly triggers: Triggers;
  private readonly tokenConfig: TokenConfig;

  public constructor(
    clock: Clock,
    triggers: Triggers,
    tokenConfig: TokenConfig
  ) {
    this.clock = clock;
    this.triggers = triggers;
    this.tokenConfig = tokenConfig;
  }

  public async generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens"
  ): Promise<Tokens> {
    const eventId = uuid.v4();
    const authTime = Math.floor(this.clock.get().getTime() / 1000);
    const sub = attributeValue("sub", user.Attributes);

    let accessToken: RawToken = {
      auth_time: authTime,
      client_id: userPoolClient.ClientId,
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      scope: "aws.cognito.signin.user.admin", // TODO: scopes
      sub,
      token_use: "access",
      username: user.Username,
    };
    let idToken: RawToken = {
      "cognito:username": user.Username,
      auth_time: authTime,
      email: attributeValue("email", user.Attributes),
      email_verified: Boolean(
        attributeValue("email_verified", user.Attributes) ?? false
      ),
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      sub,
      token_use: "id",
      ...attributesToRecord(customAttributes(user.Attributes)),
    };

    if (userGroups.length) {
      accessToken["cognito:groups"] = userGroups;
      idToken["cognito:groups"] = userGroups;
    }

    if (this.triggers.enabled("PreTokenGenerationV1")) {
      const result = await this.triggers.preTokenGenerationV1(ctx, {
        clientId: userPoolClient.ClientId,
        clientMetadata,
        source,
        userAttributes: user.Attributes,
        username: user.Username,
        groupConfiguration: {
          // TODO: this should be populated from the user's groups
          groupsToOverride: undefined,
          iamRolesToOverride: undefined,
          preferredRole: undefined,
        },
        userPoolId: userPoolClient.UserPoolId,
      });

      idToken = applyTokenOverrides(idToken, result.claimsOverrideDetails);
    }

    if (this.triggers.enabled("PreTokenGenerationV2")) {
      const result = await this.triggers.preTokenGenerationV2(ctx, {
        clientId: userPoolClient.ClientId,
        clientMetadata,
        source,
        userAttributes: user.Attributes,
        username: user.Username,
        groupConfiguration: {
          // TODO: this should be populated from the user's groups
          groupsToOverride: undefined,
          iamRolesToOverride: undefined,
          preferredRole: undefined,
        },
        userPoolId: userPoolClient.UserPoolId,
      });

      accessToken = applyTokenOverrides(
        accessToken,
        result.claimsAndScopeOverrideDetails.accessTokenGeneration
      );
      idToken = applyTokenOverrides(
        idToken,
        result.claimsAndScopeOverrideDetails.idTokenGeneration
      );
    }

    const issuer = `${this.tokenConfig.IssuerDomain}/${userPoolClient.UserPoolId}`;

    const AccessTokenExpireIn = formatExpiration(
      userPoolClient.AccessTokenValidity,
      userPoolClient.TokenValidityUnits?.AccessToken ?? "hours",
      "24h"
    );

    const IdTokenExpireIn = formatExpiration(
      userPoolClient.IdTokenValidity,
      userPoolClient.TokenValidityUnits?.IdToken ?? "hours",
      "24h"
    );

    const RefreshTokenExpireIn = formatExpiration(
      userPoolClient.RefreshTokenValidity,
      userPoolClient.TokenValidityUnits?.RefreshToken ?? "days",
      "7d"
    );
    console.log(
      "AccessTokenValidity",
      userPoolClient.AccessTokenValidity,
      typeof userPoolClient.AccessTokenValidity
    );
    console.log(
      "AccessTokenValidityUnit",
      userPoolClient.TokenValidityUnits?.AccessToken ?? "hours"
    );
    console.log("AccessTokenExpireIn", AccessTokenExpireIn);

    console.log(
      "IdTokenValidity",
      userPoolClient.IdTokenValidity,
      typeof userPoolClient.IdTokenValidity
    );
    console.log(
      "IdTokenValidityUnit",
      userPoolClient.TokenValidityUnits?.IdToken ?? "hours"
    );
    console.log("IdTokenExpireIn", IdTokenExpireIn);

    console.log(
      "RefreshTokenValidity",
      userPoolClient.RefreshTokenValidity,
      typeof userPoolClient.RefreshTokenValidity
    );
    console.log(
      "RefreshTokenValidityUnit",
      userPoolClient.TokenValidityUnits?.RefreshToken ?? "hours"
    );
    console.log("RefreshTokenExpireIn", RefreshTokenExpireIn);

    return {
      AccessToken: jwt.sign(accessToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: AccessTokenExpireIn,
        keyid: "CognitoLocal",
      }),
      IdToken: jwt.sign(idToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: IdTokenExpireIn,
        audience: userPoolClient.ClientId,
        keyid: "CognitoLocal",
      }),
      // this content is for debugging purposes only
      // in reality token payload is encrypted and uses different algorithm
      RefreshToken: jwt.sign(
        {
          "cognito:username": user.Username,
          email: attributeValue("email", user.Attributes),
          iat: authTime,
          jti: uuid.v4(),
        },
        PrivateKey.pem,
        {
          algorithm: "RS256",
          issuer,
          expiresIn: RefreshTokenExpireIn,
        }
      ),
    };
  }
}
