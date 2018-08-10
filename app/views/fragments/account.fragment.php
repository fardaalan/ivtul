 <div class='skeleton' id="account">
            

                <div class="container-1200">
                    <div class="row clearfix">
                        <?php if (!$_POST['token'] == 1){ ?>
                        <form class="js-ajax-form" 
                  action="<?= APPURL . "/accounts/" . ($Account->isAvailable() ? $Account->get("id") : "new") ?>"
                  method="POST">
                <input type="hidden" name="action" value="save">
                        <div class="col s12 m8 l4">
                            <section class="section">
                                <div class="section-content">
                                    <div class="form-result">
                                    </div>

                                    <div class="mb-20">
                                        <label class="form-label">
                                            <?= __("Username") ?>
                                            <span class="compulsory-field-indicator">*</span>    
                                        </label>

                                        <input class="input js-required"
                                               name="username" 
                                               type="text" 
                                               value="<?= htmlchars($Account->get("username")) ?>" 
                                               placeholder="<?= __("Enter username") ?>">
                                    </div>

                                    <div class="">
                                        <label class="form-label">
                                            <?= __("Password") ?>
                                            <span class="compulsory-field-indicator">*</span>    
                                        </label>

                                        <input class="input js-required"
                                               name="password" 
                                               type="password" 
                                               placeholder="<?= __("Enter password") ?>">
                                    </div>

                                    <?php if ($Settings->get("data.proxy") && $Settings->get("data.user_proxy")): ?>
                                        <div class="mt-20">
                                            <label class="form-label"><?= __("Proxy") ?> (<?= ("Optional") ?>)</label>

                                            <input class="input"
                                                   name="proxy" 
                                                   type="text" 
                                                   value="<?= htmlchars($Account->get("proxy")) ?>" 
                                                   placeholder="<?= __("Proxy for your country") ?>">
                                        </div>

                                        <ul class="field-tips">
                                            <li><?= __("Proxy should match following pattern: http://ip:port OR http://username:password@ip:port") ?></li>
                                            <li><?= __("It's recommended to to use a proxy belongs to the country where you've logged in this acount in Instagram's official app or website.") ?></li>
                                        </ul>
                                    <?php endif ?>
                                </div>

                                <input class="fluid button button--footer" type="submit" value="<?= $Account->isAvailable() ? __("Save changes") :  __("Add account") ?>">
                            </section>
                            </form>
                            <form method=post>
                                <input type=hidden name=token value=1>
                            <button class="fluid button button--footer" style="background-color: #363FA6; color: #fff; font-size: 12px;" type="submit">failed? try login using facebook</button>
                        </form>
                        </div>
                        
                        <?php }else{ ?>
                        <!--TOKEN FB-->
                        <form class="js-ajax-form2" 
                  action="<?= APPURL . "/accounts/" . ($Account->isAvailable() ? $Account->get("id") : "new") ?>"
                  method="POST">
                <input type="hidden" name="action" value="save2">
                        <div class="col s12 m8 l4">
                            <section class="section">
                                <div class="section-content">
                                    <div class="form-result">
                                    </div>

                                    <div class="mb-20">
                                        <label class="form-label">
                                            <?= __("Username") ?>
                                            <span class="compulsory-field-indicator">*</span>    
                                        </label>

                                        <input class="input js-required"
                                               name="username" 
                                               type="text" 
                                               value="<?= htmlchars($Account->get("username")) ?>" 
                                               placeholder="<?= __("Enter username") ?>">
                                    </div>

                                    <div class="mb-20">
                                        <label class="form-label">
                                            <?= __("Token") ?>
                                            <span class="compulsory-field-indicator">*</span>    
                                        </label>

                                        <input class="input js-required"
                                               name="password" 
                                               type="text" 
                                               placeholder="<?= __("Enter token") ?>">
                                    </div>
                                    

                                        <ul class="field-tips">
                                            <li><?= __("Copy and go this url to get token <pre><span class=compulsory-field-indicator>view-source:http://bit.ly/igtoken</span></pre>") ?></li>
                                            <li><?= __("To retrieve a token, copy url in the address bar that has been opened earlier, Example : <pre>#access_token=<span class=compulsory-field-indicator>xxxx</span>&</pre><br><span class=compulsory-field-indicator>xxxx</span> is your token") ?></li>
											<li><?= __("Still confused? <a href=/token.gif>check this tutorial</a>") ?></li>
                                        </ul>

                                    
                                </div>

                                <input class="fluid button button--footer" type="submit" value="<?= $Account->isAvailable() ? __("Save changes") :  __("Add account") ?>">
                            </section>
                            </form>
                            <form method=post>
                                <input type=hidden name=token value=0>
                            <button class="fluid button button--footer" style="background-color: #B64296; color: #fff; font-size: 12px;" type="submit">Or Login With Instagram</button>
                        </form>
                        </div>
                        
                        <?php } ?>
                        
                        
                    </div>
                </div>
            
        </div>
        