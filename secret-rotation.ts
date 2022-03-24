import {
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
  UpdateSecretVersionStageCommand,
} from "@aws-sdk/client-secrets-manager";
import { SecretsManagerRotationEvent } from "aws-lambda";

export type StepCommandArgs = {
  serviceClient: SecretsManagerClient;
  arn: string;
  token: string;
};

/**
 * Base class for secrets rotation
 * @see - https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_turn-on-for-other.html
 * @see - https://mechanicalrock.github.io/2020/02/03/secrets-rotation-with-secrets-manager.html
 */
export abstract class SecretsRotationStepActions {
  async doRotate(event: SecretsManagerRotationEvent) {
    const arn = event.SecretId;
    const token = event.ClientRequestToken;
    const step = event.Step;

    // Setup the client
    const serviceClient = new SecretsManagerClient({
      region: process.env.REGION || ``,
      endpoint: process.env.SECRETS_MANAGER_ENDPOINT || ``,
    });

    // Make sure the version is staged correctly
    const metadata = await serviceClient.send(
      new DescribeSecretCommand({
        SecretId: arn,
      }),
    );

    if (!metadata.RotationEnabled) {
      throw new Error(`Secret ${arn} is not enabled for rotation`);
    }

    const versions = metadata.VersionIdsToStages || {};

    if (!(token in versions)) {
      throw Error(
        `Secret version ${token} has no stage for rotation of secret ${arn}.`,
      );
    }

    if (!Object.keys(versions).includes(token)) {
      throw new Error(
        `Secret Version ${token} has no stage for rotation of secret ${arn}`,
      );
    } else if (versions[token].includes("AWSCURRENT")) {
      console.log(`Secret Version ${token} is already in "AWSCURRENT" stage.`);
      return;
    } else if (!versions[token].includes("AWSPENDING")) {
      throw new Error(
        `Secret version ${token} not set as AWSPENDING for rotation of secret ${arn}.`,
      );
    }

    // execute method based on step
    await this[step]({
      serviceClient,
      arn,
      token,
    });
  }

  async createSecret(args: StepCommandArgs) {
    console.log("createSecret: start");

    const current_secret = await args.serviceClient.send(
      new GetSecretValueCommand({
        SecretId: args.arn,
        VersionStage: `AWSCURRENT`,
      }),
    );

    if (!current_secret || !current_secret.SecretString) {
      throw new Error(`No current secret`);
    }

    console.log(
      `Successfully retrieved AWSCURRENT secret for ` + current_secret.Name,
    );

    // Now try to get the PENDING secret version, if that fails, generates and stores a new secret
    try {
      const pending_secret = await args.serviceClient.send(
        new GetSecretValueCommand({
          SecretId: args.arn,
          VersionId: args.token,
          VersionStage: `AWSPENDING`,
        }),
      );

      console.log(
        `Successfully retrieved AWSPENDING secret for ${pending_secret.Name}, no further operation needed.`,
      );
    } catch (err) {
      if ((err as Error).name !== "ResourceNotFoundException") {
        throw err;
      }

      console.log(
        `secret ${current_secret.Name} didn't exist in AWSPENDING. Generating new secret for AWSPENDING stage.`,
      );

      const new_secret = await this.generateSecret(args);

      await args.serviceClient.send(
        new PutSecretValueCommand({
          SecretId: args.arn,
          ClientRequestToken: args.token,
          SecretString: new_secret,
          VersionStages: [`AWSPENDING`],
        }),
      );

      console.log(
        `Successfully created AWSPENDING for secret ${current_secret.Name}.`,
      );
    }

    console.log("createSecret: complete");
  }

  /**
   * Method to effectively generate a new secret in order to store it in SecretsManager.
   */
  abstract generateSecret(args: StepCommandArgs): Promise<string>;

  /**
   * Sets the secret in service.
   * This method should set the AWSPENDING secret in the service that the secret belongs to.
   * For example, if the secret is a database credential, this method should take the value of the AWSPENDING secret and set the user's password
   * to this value in the database.
   * @param args
   */
  abstract setSecret(args: StepCommandArgs): Promise<void>;

  /**
   * This method should validate that the AWSPENDING secret works in the service that the secret belongs to.
   * For example, if the secret is a database credential, this method should validate that the user can login
   * with the password in AWSPENDING and that the user has all of the expected permissions against the database.
   * @param args arguments for StepCommand
   */
  abstract testSecret(args: StepCommandArgs): Promise<void>;

  /**
   * Finish the secret
   * This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
   * @param args
   * @returns
   */
  async finishSecret(args: StepCommandArgs) {
    console.log("finishSecret: start");

    // First describe the secret to get the current version
    const metadata = await args.serviceClient.send(
      new DescribeSecretCommand({ SecretId: args.arn }),
    );

    let current_version = `None`;

    if (metadata.VersionIdsToStages == undefined) {
      throw new Error(`No VersionIdsToStages`);
    }

    for (const version in metadata.VersionIdsToStages) {
      if (metadata.VersionIdsToStages[version].includes("AWSCURRENT")) {
        if (version === args.token) {
          // The correct version is already marked as current, return
          console.log(
            `Version ${version} already marked as AWSCURRENT for ${metadata.Name}, no further operation needed.`,
          );
          return;
        }
        current_version = version;
        break;
      }
    }

    if (current_version === "None") {
      throw new Error("No matching version found in metadata.");
    }

    // Finalize by staging the secret version current
    await args.serviceClient.send(
      new UpdateSecretVersionStageCommand({
        SecretId: args.arn,
        VersionStage: `AWSCURRENT`,
        MoveToVersionId: args.token,
        RemoveFromVersionId: current_version,
      }),
    );
    console.log(
      `Successfully set AWSCURRENT stage for secret ${metadata.Name}.`,
    );

    console.log("finishSecret: complete");
  }
}
