import { AppCommand } from "../AppCommand";
import * as Store from "../../StoreTypes";

export class HideIntegrationToolsDialog extends AppCommand {

    /**
     * Creates a new {@link HideIntegrationToolsDialog}.
     * @param context
     *  The application context.
     */
    constructor(context: Store.ApplicationStore) {
        super(context);
    }

    /**
     * Executes the command.
     */
    execute(): void {
        this._context.isShowingIntegrationToolsDialog = false;
    }

}